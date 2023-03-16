/* ----------------------------------------------------------------------------
  Copyright (c) 2021, Daan Leijen
  This is free software; you can redistribute it and/or modify it
  under the terms of the MIT License. A copy of the license can be
  found in the "LICENSE" file at the root of this distribution.
-----------------------------------------------------------------------------*/
// #include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>  
#include <sys/stat.h>
#include <sys/mman.h>

#include "../include/isocline.h"
#include "common.h"
#include "history.h"
#include "stringbuf.h"

#define IC_MAX_HISTORY   (100000)
#define IC_AVG_ENTRY_LEN (100)
#define IC_MMAP_SIZE     (IC_MAX_HISTORY * IC_AVG_ENTRY_LEN)

struct history_s {
  ssize_t      len;               // size limit of elems (max number of entries)
  ssize_t      count;             // current number of entries in use
  const char** elems;             // history items (up to count)
  const char*  fname;             // history file name
  int          fd;                // history file descriptor
  size_t       fsize;             // history file size
  size_t       fmem_size;         // size of memory mapped region
  void*        fmem;              // memory mapped to history file
  alloc_t*     mem;               // memory allocator
  bool         allow_duplicates;  // allow duplicate entries?
};

ic_private history_t* history_new( alloc_t* mem ) {
  history_t* h = mem_zalloc_tp(mem,history_t);
  h->elems = mem_zalloc(mem, IC_MAX_HISTORY * sizeof(char*));
  h->mem = mem;
  return h;
}

ic_private void history_free( history_t* h ) {
  if (h == NULL) return;
  history_clear(h);
  mem_free(h->mem, h->elems);
  h->elems = NULL;
  h->len = 0;
  munmap(h->fmem, h->fmem_size);
  close(h->fd);
  mem_free(h->mem, h->fname);
  h->fname = NULL;
  mem_free(h->mem, h); // free ourselves
}

ic_private bool history_enable_duplicates( history_t* h, bool enable ) {
  bool prev = h->allow_duplicates;
  h->allow_duplicates = enable;
  return prev;
}

ic_private ssize_t history_count(const history_t* h) {
  return h->count;
}

//-------------------------------------------------------------
// push / delete
//-------------------------------------------------------------

ic_private bool history_update( history_t* h, const char* entry ) {
  if (entry==NULL) return false;
  history_remove_last(h);
  history_push(h,entry);
  debug_msg("history: update: with %s; now at %s\n", entry, history_get(h,0));
  return true;
}

/// FIXME implement history_delete_at()
static void history_delete_at( history_t* h, ssize_t idx ) {
  if (idx < 0 || idx >= h->count) return;
  /// Move memory entries after index to index
  /// FIXME size of memory block that is copied is not correct
  if (idx < h->count-1) {
    memmove((void*)h->elems[idx], h->elems[idx+1], (size_t)(h->elems[h->count] - h->elems[idx+1]));
  }
  /// Substract length of entry at index from all elems pointers after index
  for (ssize_t i = idx+1; i < h->count; i++) {
    h->elems[i-1] -= h->elems[idx+1] - h->elems[idx];
  }
  /// Update file size

  // mem_free(h->mem, h->elems[idx]);
  // for(ssize_t i = idx+1; i < h->count; i++) {
    // h->elems[i-1] = h->elems[i];
  // }

  h->count--;
}

/// FIXME implement duplicate removal with memory map
/// FIXME implement insertion of an entry at the end of the history file
ic_private bool history_push( history_t* h, const char* entry ) {
  if (h->len <= 0 || entry==NULL)  return false;
  // remove any older duplicate
  if (!h->allow_duplicates) {
    for( int i = 0; i < h->count; i++) {
      if (strcmp(h->elems[i],entry) == 0) {
        history_delete_at(h,i);
      }
    }
  }
  // insert at front
  if (h->count == h->len) {
    // delete oldest entry
    history_delete_at(h,0);    
  }
  assert(h->count < h->len);
  // h->elems[h->count] = mem_strdup(h->mem,entry);
  h->count++;
  return true;
}


/// FIXME implement history_remove_last_n()
static void history_remove_last_n( history_t* h, ssize_t n ) {
  if (n <= 0) return;
  if (n > h->count) n = h->count;
  // for( ssize_t i = h->count - n; i < h->count; i++) {
    // mem_free( h->mem, h->elems[i] );
  // }
  h->count -= n;
  assert(h->count >= 0);    
}

ic_private void history_remove_last(history_t* h) {
  history_remove_last_n(h,1);
}

ic_private void history_clear(history_t* h) {
  history_remove_last_n( h, h->count );
}

ic_private const char* history_get( const history_t* h, ssize_t n ) {
  if (n < 0 || n >= h->count) return NULL;
  return h->elems[h->count - n - 1];
}

/// FIXME replace strstr() with s.th. like GNU libc memmem()
ic_private bool history_search( const history_t* h, ssize_t from /*including*/, const char* search, bool backward, ssize_t* hidx, ssize_t* hpos ) {
  const char* p = NULL;
  ssize_t i;
  if (backward) {
    for( i = from; i < h->count; i++ ) {
      // p = strstr( history_get(h,i), search);
      // p = memem(
        // history_get(h,i), history_get(h,i+1) - history_get(h,i),
        // search, strlen(search));
      if (p != NULL) break;
    }
  }
  else {
    for( i = from; i >= 0; i-- ) {
      p = strstr( history_get(h,i), search);
      if (p != NULL) break;
    }
  }
  if (p == NULL) return false;
  if (hidx != NULL) *hidx = i;
  if (hpos != NULL) *hpos = (p - history_get(h,i));
  return true;
}

//-------------------------------------------------------------
// 
//-------------------------------------------------------------

ic_private void history_load_from( history_t* h, const char* fname, long max_entries ) {
  history_clear(h);
  h->fname = mem_strdup(h->mem,fname);
  if (max_entries == 0) {
    assert(h->elems == NULL);
    return;
  }
  if (max_entries < 0 || max_entries > IC_MAX_HISTORY) max_entries = IC_MAX_HISTORY;
  // h->elems = (const char**)mem_zalloc_tp_n(h->mem, char*, max_entries );
  // if (h->elems == NULL) return;
  h->len = max_entries;
  history_load(h);
}




//-------------------------------------------------------------
// save/load history to file
//-------------------------------------------------------------

static char from_xdigit( int c ) {
  if (c >= '0' && c <= '9') return (char)(c - '0');
  if (c >= 'A' && c <= 'F') return (char)(10 + (c - 'A'));
  if (c >= 'a' && c <= 'f') return (char)(10 + (c - 'a'));
  return 0;
}

static char to_xdigit( uint8_t c ) {
  if (c <= 9) return ((char)c + '0');
  if (c >= 10 && c <= 15) return ((char)c - 10 + 'A');
  return '0';
}

static bool ic_isxdigit( int c ) {
  return ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9'));
}

// static bool history_read_entry( history_t* h, stringbuf_t* sbuf ) {
  // sbuf_clear(sbuf);
  // while( !feof(f)) {
    // int c = fgetc(f);
    // if (c == EOF || c == '\n') break;
    // if (c == '\\') {
      // c = fgetc(f);
      // if (c == 'n')       { sbuf_append(sbuf,"\n"); }
      // else if (c == 'r')  { /* ignore */ }  // sbuf_append(sbuf,"\r");
      // else if (c == 't')  { sbuf_append(sbuf,"\t"); }
      // else if (c == '\\') { sbuf_append(sbuf,"\\"); }
      // else if (c == 'x') {
        // int c1 = fgetc(f);
        // int c2 = fgetc(f);
        // if (ic_isxdigit(c1) && ic_isxdigit(c2)) {
          // char chr = from_xdigit(c1)*16 + from_xdigit(c2);
          // sbuf_append_char(sbuf,chr);
        // }
        // else return false;
      // }
      // else return false;
    // }
    // else sbuf_append_char(sbuf,(char)c);
  // }
  // if (sbuf_len(sbuf)==0 || sbuf_string(sbuf)[0] == '#') return true;
  // return history_push(h, sbuf_string(sbuf));
// }

// static bool history_write_entry( const char* entry, stringbuf_t* sbuf ) {
  // sbuf_clear(sbuf);
  // //debug_msg("history: write: %s\n", entry);
  // while( entry != NULL && *entry != 0 ) {
    // char c = *entry++;
    // if (c == '\\')      { sbuf_append(sbuf,"\\\\"); }
    // else if (c == '\n') { sbuf_append(sbuf,"\\n"); }
    // else if (c == '\r') { /* ignore */ } // sbuf_append(sbuf,"\\r"); }
    // else if (c == '\t') { sbuf_append(sbuf,"\\t"); }
    // else if (c < ' ' || c > '~' || c == '#') {
      // char c1 = to_xdigit( (uint8_t)c / 16 );
      // char c2 = to_xdigit( (uint8_t)c % 16 );
      // sbuf_append(sbuf,"\\x");
      // sbuf_append_char(sbuf,c1);
      // sbuf_append_char(sbuf,c2);
    // }
    // else sbuf_append_char(sbuf,c);
  // }
  // //debug_msg("history: write buf: %s\n", sbuf_string(sbuf));
  //
  // if (sbuf_len(sbuf) > 0) {
    // sbuf_append(sbuf,"\n");
    // fputs(sbuf_string(sbuf),f);
  // }
  // return true;
// }

ic_private void history_load( history_t* h ) {
  if (h->fname == NULL) return;
  h->fd = open(h->fname, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (h->fd < 0) return;
  struct stat statbuf;
  if (fstat(h->fd, &statbuf) < 0) return;
  h->fsize = (size_t)statbuf.st_size;
  if (h->fsize == 0) return;
  h->fmem_size = IC_MMAP_SIZE;
  h->fmem = mmap(NULL, h->fmem_size, PROT_READ | PROT_WRITE, MAP_SHARED, h->fd, 0);
  if (h->fmem == MAP_FAILED) return;
  char *base = h->fmem;
  size_t bytes_scanned = 0;
  while(bytes_scanned < h->fsize) {
    char *nl = memchr(base, '\n', h->fsize - bytes_scanned);
    if (!nl) {
      debug_msg("warning: history file doesn't end with a newline\n");
      break;
    }
    h->elems[h->count] = base;
    bytes_scanned += (size_t)(nl - base + 1);
    base = nl + 1;
    h->count++;
  }
  debug_msg("scanned %d history entries\n", h->count);
  // stringbuf_t* sbuf = sbuf_new(h->mem);
  // if (sbuf != NULL) {
    // while (!feof(f)) {
      // if (!history_read_entry(h,f,sbuf)) break; // error
    // }
    // sbuf_free(sbuf);
  // }
}

ic_private void history_save( const history_t* h ) {
  if (h->fd < 0) return;
  msync(h->fmem, h->fsize, MS_ASYNC);
  // #ifndef _WIN32
  // chmod(h->fname,S_IRUSR|S_IWUSR);
  // #endif
  // stringbuf_t* sbuf = sbuf_new(h->mem);
  // if (sbuf != NULL) {
    // for( int i = 0; i < h->count; i++ )  {
      // if (!history_write_entry(h->elems[i],f,sbuf)) break;  // error
    // }
    // sbuf_free(sbuf);
  // }
  // close(h->fd);
}
