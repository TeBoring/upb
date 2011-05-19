/*
 * upb - a minimalist implementation of protocol buffers.
 *
 * Copyright (c) 2010-2011 Google Inc.  See LICENSE for details.
 * Author: Josh Haberman <jhaberman@gmail.com>
 *
 * Data structure for storing a message of protobuf data.  Unlike Google's
 * protobuf, upb_msg and upb_array are reference counted instead of having
 * exclusive ownership of their fields.  This is a better match for dynamic
 * languages where statements like a.b = other_b are normal.
 *
 * upb's parsers and serializers could also be used to populate and serialize
 * other kinds of message objects (even one generated by Google's protobuf).
 *
 * TODO: consider properly supporting const instances.
 */

#ifndef UPB_MSG_H
#define UPB_MSG_H

#include <stdlib.h>
#include "upb_handlers.h"

#ifdef __cplusplus
extern "C" {
#endif

// A pointer to a .proto value.  The owner must have an out-of-band way of
// knowing the type, so it knows which union member to use.
typedef union {
  double *_double;
  float *_float;
  int32_t *int32;
  int64_t *int64;
  uint8_t *uint8;
  uint32_t *uint32;
  uint64_t *uint64;
  bool *_bool;
  upb_string **str;
  upb_msg **msg;
  upb_array **arr;
  void *_void;
} upb_valueptr;

INLINE upb_valueptr upb_value_addrof(upb_value *val) {
  upb_valueptr ptr = {&val->val._double};
  return ptr;
}

// Reads or writes a upb_value from an address represented by a upb_value_ptr.
// We need to know the value type to perform this operation, because we need to
// know how much memory to copy (and for big-endian machines, we need to know
// where in the upb_value the data goes).
//
// For little endian-machines where we didn't mind overreading, we could make
// upb_value_read simply use memcpy().
INLINE upb_value upb_value_read(upb_valueptr ptr, upb_fieldtype_t ft) {
  upb_value val;

#ifdef NDEBUG
#define CASE(t, member_name) \
  case UPB_TYPE(t): val.val.member_name = *ptr.member_name; break;
#else
#define CASE(t, member_name) \
  case UPB_TYPE(t): val.val.member_name = *ptr.member_name; val.type = upb_types[ft].inmemory_type; break;
#endif

  switch(ft) {
    CASE(DOUBLE,   _double)
    CASE(FLOAT,    _float)
    CASE(INT32,    int32)
    CASE(INT64,    int64)
    CASE(UINT32,   uint32)
    CASE(UINT64,   uint64)
    CASE(SINT32,   int32)
    CASE(SINT64,   int64)
    CASE(FIXED32,  uint32)
    CASE(FIXED64,  uint64)
    CASE(SFIXED32, int32)
    CASE(SFIXED64, int64)
    CASE(BOOL,     _bool)
    CASE(ENUM,     int32)
    CASE(STRING,   str)
    CASE(BYTES,    str)
    CASE(MESSAGE,  msg)
    CASE(GROUP,    msg)
    case UPB_VALUETYPE_ARRAY:
      val.val.arr = *ptr.arr;
#ifndef NDEBUG
      val.type = UPB_VALUETYPE_ARRAY;
#endif
      break;
    default: assert(false);
  }
  return val;

#undef CASE
}

INLINE void upb_value_write(upb_valueptr ptr, upb_value val,
                            upb_fieldtype_t ft) {
#ifndef NDEBUG
  if (ft == UPB_VALUETYPE_ARRAY) {
    assert(val.type == UPB_VALUETYPE_ARRAY);
  } else if (val.type != UPB_VALUETYPE_RAW) {
    assert(val.type == upb_types[ft].inmemory_type);
  }
#endif
#define CASE(t, member_name) \
  case UPB_TYPE(t): *ptr.member_name = val.val.member_name; break;

  switch(ft) {
    CASE(DOUBLE,   _double)
    CASE(FLOAT,    _float)
    CASE(INT32,    int32)
    CASE(INT64,    int64)
    CASE(UINT32,   uint32)
    CASE(UINT64,   uint64)
    CASE(SINT32,   int32)
    CASE(SINT64,   int64)
    CASE(FIXED32,  uint32)
    CASE(FIXED64,  uint64)
    CASE(SFIXED32, int32)
    CASE(SFIXED64, int64)
    CASE(BOOL,     _bool)
    CASE(ENUM,     int32)
    CASE(STRING,   str)
    CASE(BYTES,    str)
    CASE(MESSAGE,  msg)
    CASE(GROUP,    msg)
    case UPB_VALUETYPE_ARRAY:
      *ptr.arr = val.val.arr;
      break;
    default: assert(false);
  }

#undef CASE
}


/* upb_array ******************************************************************/

typedef uint32_t upb_arraylen_t;
struct _upb_array {
  upb_atomic_refcount_t refcount;
  // "len" and "size" are measured in elements, not bytes.
  upb_arraylen_t len;
  upb_arraylen_t size;
  char *ptr;
};

void _upb_array_free(upb_array *a, upb_fielddef *f);
INLINE upb_valueptr _upb_array_getptrforsize(upb_array *a, size_t type_size,
                                             uint32_t elem) {
  upb_valueptr p;
  p._void = &a->ptr[elem * type_size];
  return p;
}

INLINE upb_valueptr _upb_array_getptr(upb_array *a, upb_fielddef *f,
                                      uint32_t elem) {
  return _upb_array_getptrforsize(a, upb_types[f->type].size, elem);
}

upb_array *upb_array_new(void);

INLINE void upb_array_unref(upb_array *a, upb_fielddef *f) {
  if (a && upb_atomic_unref(&a->refcount)) _upb_array_free(a, f);
}

void upb_array_recycle(upb_array **arr);
INLINE uint32_t upb_array_len(upb_array *a) {
  return a->len;
}

INLINE upb_value upb_array_get(upb_array *arr, upb_fielddef *f,
                               upb_arraylen_t i) {
  assert(i < upb_array_len(arr));
  return upb_value_read(_upb_array_getptr(arr, f, i), f->type);
}


/* upb_msg ********************************************************************/

// upb_msg is not self-describing; the upb_msg does not contain a pointer to the
// upb_msgdef.  While this makes the API a bit more cumbersome to use, this
// choice was made for a few important reasons:
//
// 1. it would make every message 8 bytes larger on 64-bit platforms.  This is
//    a high overhead for small messages.
// 2. you would want the msg to own a ref on its msgdef, but this would require
//    an atomic operation for every message create or destroy!
struct _upb_msg {
  upb_atomic_refcount_t refcount;
  uint8_t data[4];  // We allocate the appropriate amount per message.
};

void _upb_msg_free(upb_msg *msg, upb_msgdef *md);

INLINE upb_valueptr _upb_msg_getptr(upb_msg *msg, upb_fielddef *f) {
  upb_valueptr p;
  p._void = &msg->data[f->byte_offset];
  return p;
}

// Creates a new msg of the given type.
upb_msg *upb_msg_new(upb_msgdef *md);

// Unrefs the given message.
INLINE void upb_msg_unref(upb_msg *msg, upb_msgdef *md) {
  if (msg && upb_atomic_unref(&msg->refcount)) _upb_msg_free(msg, md);
}

INLINE upb_msg *upb_msg_getref(upb_msg *msg) {
  assert(msg);
  upb_atomic_ref(&msg->refcount);
  return msg;
}

// Modifies *msg to point to a newly initialized msg instance.  If the msg had
// no other referents, reuses the same msg, otherwise allocates a new one.
// The caller *must* own a ref on the msg prior to calling this method!
void upb_msg_recycle(upb_msg **msg, upb_msgdef *msgdef);

// Tests whether the given field is explicitly set, or whether it will return a
// default.
INLINE bool upb_msg_has(upb_msg *msg, upb_fielddef *f) {
  return (msg->data[f->set_bit_offset] & f->set_bit_mask) != 0;
}

// We have several options for handling default values:
// 1. inside upb_msg_clear(), overwrite all values to be their defaults,
//    overwriting submessage pointers to point to the default instance again.
// 2. inside upb_msg_get(), test upb_msg_has() and return md->default_value
//    if it is not set.  upb_msg_clear() only clears the set bits.
//    We lazily clear objects if/when we reuse them.
// 3. inside upb_msg_clear(), overwrite all values to be their default,
//    and recurse into submessages to set all their values to defaults also.
// 4. as a hybrid of (1) and (3), clear all set bits in upb_msg_clear()
//    but also overwrite all primitive values to be their defaults.  Only
//    accessors for non-primitive values (submessage, strings, and arrays)
//    need to check the has-bits in their accessors -- primitive values can
//    always be returned straight from the msg.
//
// (1) is undesirable, because it prevents us from caching sub-objects.
// (2) makes clear() cheaper, but makes get() branchier.
// (3) makes get() less branchy, but makes clear() traverse the message graph.
// (4) is probably the best bang for the buck.
//
// For the moment upb does (2), but we should implement (4).  Google's protobuf
// does (3), which is likely part of the reason that even our table-based
// decoder beats it in some benchmarks.

// For submessages and strings, the returned value is not owned.
upb_value upb_msg_get(upb_msg *msg, upb_fielddef *f);

// A specialized version of the previous that is cheaper because it doesn't
// support submessages or arrays.
INLINE upb_value upb_msg_getscalar(upb_msg *msg, upb_fielddef *f) {
  if (upb_msg_has(msg, f)) {
    return upb_value_read(_upb_msg_getptr(msg, f), upb_field_valuetype(f));
  } else {
    return f->default_value;
  }
}

// Sets the given field to the given value.  If the field is a string, array,
// or submessage, releases the ref on any object we may have been referencing
// and takes a ref on the new object (if any).
void upb_msg_set(upb_msg *msg, upb_fielddef *f, upb_value val);

// Unsets all field values back to their defaults.
INLINE void upb_msg_clear(upb_msg *msg, upb_msgdef *md) {
  memset(msg->data, 0, md->set_flags_bytes);
}

// Registers handlers for populating a msg for the given upb_msgdef.
// The upb_msg itself must be passed as the param to the src.
upb_mhandlers *upb_msg_reghandlers(upb_handlers *h, upb_msgdef *md);


/* upb_msgvisitor *************************************************************/

// Calls a set of upb_handlers with the contents of a upb_msg.
typedef struct {
  upb_fhandlers *fh;
  upb_fielddef *f;
  uint16_t msgindex;  // Only when upb_issubmsg(f).
} upb_msgvisitor_field;

typedef struct {
  upb_msgvisitor_field *fields;
  int fields_len;
} upb_msgvisitor_msg;

typedef struct {
  uint16_t msgindex;
  uint16_t fieldindex;
  uint32_t arrayindex;  // UINT32_MAX if not an array frame.
} upb_msgvisitor_frame;

typedef struct {
  upb_msgvisitor_msg *messages;
  int messages_len;
  upb_dispatcher dispatcher;
} upb_msgvisitor;

// Initializes a msgvisitor that will push data from messages of the given
// msgdef to the given set of handlers.
void upb_msgvisitor_init(upb_msgvisitor *v, upb_msgdef *md, upb_handlers *h);
void upb_msgvisitor_uninit(upb_msgvisitor *v);

void upb_msgvisitor_reset(upb_msgvisitor *v, upb_msg *m);
void upb_msgvisitor_visit(upb_msgvisitor *v, upb_status *status);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif