
#line 1 "upb/json/parser.rl"
/*
** upb::json::Parser (upb_json_parser)
**
** A parser that uses the Ragel State Machine Compiler to generate
** the finite automata.
**
** Ragel only natively handles regular languages, but we can manually
** program it a bit to handle context-free languages like JSON, by using
** the "fcall" and "fret" constructs.
**
** This parser can handle the basics, but needs several things to be fleshed
** out:
**
** - handling of unicode escape sequences (including high surrogate pairs).
** - properly check and report errors for unknown fields, stack overflow,
**   improper array nesting (or lack of nesting).
** - handling of base64 sequences with padding characters.
** - handling of push-back (non-success returns from sink functions).
** - handling of keys/escape-sequences/etc that span input buffers.
*/

#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "upb/json/parser.h"

#define UPB_JSON_MAX_DEPTH 64

/* Well known type messages have different json format from other normal
 * messages. For these messages, we need to handle them specially. */
enum {
  /* Processing normal messages. */
  WELL_KNOWN_NORMAL = 0,
  /* Processing google.protobuf.Any. */
  WELL_KNOWN_ANY = 1
};

/* Phases for parsing Any */
enum {
  /* Not started. */
  PARSE_ANY_NOT_STARTED = 0,
  /* Looking for type url. */
  PARSE_ANY_ROUND1 = 1,
  /* type url is found. Need to parse Any again */
  PARSE_ANY_ROUND2 = 2,
  /* Needs to switch to the second phase. */
  PARSE_ANY_SWITCH = 3,
  /* Parsing has finished. */
  PARSE_ANY_FINISH = 4,
};

typedef struct {
  upb_byteshandler handler;
  upb_bytessink sink;
  char *ptr;
  size_t len, size;
} upb_stringsink;


static void *stringsink_start(void *_sink, const void *hd, size_t size_hint) {
  upb_stringsink *sink = _sink;
  sink->len = 0;
  return sink;
}

static size_t stringsink_string(void *_sink, const void *hd, const char *ptr,
                                size_t len, const upb_bufhandle *handle) {
  upb_stringsink *sink = _sink;
  size_t new_size = sink->size;

  UPB_UNUSED(hd);
  UPB_UNUSED(handle);

  while (sink->len + len > new_size) {
    new_size *= 2;
  }

  if (new_size != sink->size) {
    sink->ptr = realloc(sink->ptr, new_size);
    sink->size = new_size;
  }

  memcpy(sink->ptr + sink->len, ptr, len);
  sink->len += len;

  return len;
}

void upb_stringsink_init(upb_stringsink *sink) {
  upb_byteshandler_init(&sink->handler);
  upb_byteshandler_setstartstr(&sink->handler, stringsink_start, NULL);
  upb_byteshandler_setstring(&sink->handler, stringsink_string, NULL);

  upb_bytessink_reset(&sink->sink, &sink->handler, sink);

  sink->size = 32;
  sink->ptr = malloc(sink->size);
  sink->len = 0;
}

void upb_stringsink_uninit(upb_stringsink *sink) { free(sink->ptr); }

typedef struct {
  /* For encoding Any payload values */
  const upb_handlers *any_payload_serialize_handlers;
  upb_json_parsermethod *method;
  upb_pb_encoder *encoder;
  upb_stringsink sink;
} upb_any_jsonparser_frame;

typedef struct {
  upb_sink sink;

  /* The current message in which we're parsing, and the field whose value we're
   * expecting next. */
  const upb_msgdef *m;
  const upb_fielddef *f;

  /* The table mapping json name to fielddef for this message. */
  upb_strtable *name_table;

  /* We are in a repeated-field context, ready to emit mapentries as
   * submessages. This flag alters the start-of-object (open-brace) behavior to
   * begin a sequence of mapentry messages rather than a single submessage. */
  bool is_map;

  /* We are in a map-entry message context. This flag is set when parsing the
   * value field of a single map entry and indicates to all value-field parsers
   * (subobjects, strings, numbers, and bools) that the map-entry submessage
   * should end as soon as the value is parsed. */
  bool is_mapentry;

  /* If |is_map| or |is_mapentry| is true, |mapfield| refers to the parent
   * message's map field that we're currently parsing. This differs from |f|
   * because |f| is the field in the *current* message (i.e., the map-entry
   * message itself), not the parent's field that leads to this map. */
  const upb_fielddef *mapfield;

  /* Record Any start point. See details in parser.rl */
  const char *any_start;

  /* Record Any parsing stage. See details in parser.rl */
  int parse_any_round;

  /* This flag specify what kind of well known type message is being processed.
   */
  int well_known_type;

  /* For parsing Any */
  upb_any_jsonparser_frame *any_jsonparser_frame;
} upb_jsonparser_frame;

struct upb_json_parser {
  upb_env *env;
  const upb_json_parsermethod *method;
  upb_bytessink input_;

  /* Stack to track the JSON scopes we are in. */
  upb_jsonparser_frame stack[UPB_JSON_MAX_DEPTH];
  upb_jsonparser_frame *top;
  upb_jsonparser_frame *limit;

  upb_status status;

  /* Ragel's internal parsing stack for the parsing state machine. */
  int current_state;
  int parser_stack[UPB_JSON_MAX_DEPTH];
  int parser_top;

  /* The handle for the current buffer. */
  const upb_bufhandle *handle;

  /* Accumulate buffer.  See details in parser.rl. */
  const char *accumulated;
  size_t accumulated_len;
  char *accumulate_buf;
  size_t accumulate_buf_size;

  /* Multi-part text data.  See details in parser.rl. */
  int multipart_state;
  upb_selector_t string_selector;

  /* Input capture.  See details in parser.rl. */
  const char *capture;

  /* Intermediate result of parsing a unicode escape sequence. */
  uint32_t digit;

  /* Resolve type url when parsing Any. */
  const upb_symtab *symbol_table;
  const upb_msgdef *any_msgdef;
};

struct upb_json_parsermethod {
  upb_refcounted base;

  upb_byteshandler input_handler_;

  /* Mainly for the purposes of refcounting, so all the fielddefs we point
   * to stay alive. */
  const upb_msgdef *msg;

  /* Keys are upb_msgdef*, values are upb_strtable (json_name -> fielddef) */
  upb_inttable name_tables;
};

#define PARSER_CHECK_RETURN(x) if (!(x)) return false

/* Used to signal that a capture has been suspended. */
static char suspend_capture;

static upb_selector_t getsel_for_handlertype(upb_json_parser *p,
                                             upb_handlertype_t type) {
  upb_selector_t sel;
  bool ok = upb_handlers_getselector(p->top->f, type, &sel);
  UPB_ASSERT(ok);
  return sel;
}

static int get_well_known_type(upb_json_parser *p) {
  if (p->top->m == p->any_msgdef) {
    return WELL_KNOWN_ANY;
  } else {
    return WELL_KNOWN_NORMAL;
  }
}

static upb_selector_t parser_getsel(upb_json_parser *p) {
  return getsel_for_handlertype(
      p, upb_handlers_getprimitivehandlertype(p->top->f));
}

static bool check_stack_start(upb_json_parser *p) {
  return p->top == p->stack;
}

static bool check_stack(upb_json_parser *p) {
  if ((p->top + 1) == p->limit) {
    upb_status_seterrmsg(&p->status, "Nesting too deep");
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  return true;
}

static void set_name_table(upb_json_parser *p, upb_jsonparser_frame *frame) {
  upb_value v;
  bool ok = upb_inttable_lookupptr(&p->method->name_tables, frame->m, &v);
  UPB_ASSERT(ok);
  frame->name_table = upb_value_getptr(v);
}

static void set_any_name_table(upb_json_parser *p, upb_jsonparser_frame *frame) {
  upb_value v;
  bool ok = upb_inttable_lookupptr(
      &p->top->any_jsonparser_frame->method->name_tables, frame->m, &v);
  UPB_ASSERT(ok);
  frame->name_table = upb_value_getptr(v);
}

/* There are GCC/Clang built-ins for overflow checking which we could start
 * using if there was any performance benefit to it. */

static bool checked_add(size_t a, size_t b, size_t *c) {
  if (SIZE_MAX - a < b) return false;
  *c = a + b;
  return true;
}

static size_t saturating_multiply(size_t a, size_t b) {
  /* size_t is unsigned, so this is defined behavior even on overflow. */
  size_t ret = a * b;
  if (b != 0 && ret / b != a) {
    ret = SIZE_MAX;
  }
  return ret;
}


/* Base64 decoding ************************************************************/

/* TODO(haberman): make this streaming. */

static const signed char b64table[] = {
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      62/*+*/, -1,      -1,      -1,      63/*/ */,
  52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
  60/*8*/, 61/*9*/, -1,      -1,      -1,      -1,      -1,      -1,
  -1,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
  07/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
  15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
  23/*X*/, 24/*Y*/, 25/*Z*/, -1,      -1,      -1,      -1,      -1,
  -1,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
  33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
  41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
  49/*x*/, 50/*y*/, 51/*z*/, -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1
};

/* Returns the table value sign-extended to 32 bits.  Knowing that the upper
 * bits will be 1 for unrecognized characters makes it easier to check for
 * this error condition later (see below). */
int32_t b64lookup(unsigned char ch) { return b64table[ch]; }

/* Returns true if the given character is not a valid base64 character or
 * padding. */
bool nonbase64(unsigned char ch) { return b64lookup(ch) == -1 && ch != '='; }

static bool base64_push(upb_json_parser *p, upb_selector_t sel, const char *ptr,
                        size_t len) {
  const char *limit = ptr + len;
  for (; ptr < limit; ptr += 4) {
    uint32_t val;
    char output[3];

    if (limit - ptr < 4) {
      upb_status_seterrf(&p->status,
                         "Base64 input for bytes field not a multiple of 4: %s",
                         upb_fielddef_name(p->top->f));
      upb_env_reporterror(p->env, &p->status);
      return false;
    }

    val = b64lookup(ptr[0]) << 18 |
          b64lookup(ptr[1]) << 12 |
          b64lookup(ptr[2]) << 6  |
          b64lookup(ptr[3]);

    /* Test the upper bit; returns true if any of the characters returned -1. */
    if (val & 0x80000000) {
      goto otherchar;
    }

    output[0] = val >> 16;
    output[1] = (val >> 8) & 0xff;
    output[2] = val & 0xff;
    upb_sink_putstring(&p->top->sink, sel, output, 3, NULL);
  }
  return true;

otherchar:
  if (nonbase64(ptr[0]) || nonbase64(ptr[1]) || nonbase64(ptr[2]) ||
      nonbase64(ptr[3]) ) {
    upb_status_seterrf(&p->status,
                       "Non-base64 characters in bytes field: %s",
                       upb_fielddef_name(p->top->f));
    upb_env_reporterror(p->env, &p->status);
    return false;
  } if (ptr[2] == '=') {
    uint32_t val;
    char output;

    /* Last group contains only two input bytes, one output byte. */
    if (ptr[0] == '=' || ptr[1] == '=' || ptr[3] != '=') {
      goto badpadding;
    }

    val = b64lookup(ptr[0]) << 18 |
          b64lookup(ptr[1]) << 12;

    UPB_ASSERT(!(val & 0x80000000));
    output = val >> 16;
    upb_sink_putstring(&p->top->sink, sel, &output, 1, NULL);
    return true;
  } else {
    uint32_t val;
    char output[2];

    /* Last group contains only three input bytes, two output bytes. */
    if (ptr[0] == '=' || ptr[1] == '=' || ptr[2] == '=') {
      goto badpadding;
    }

    val = b64lookup(ptr[0]) << 18 |
          b64lookup(ptr[1]) << 12 |
          b64lookup(ptr[2]) << 6;

    output[0] = val >> 16;
    output[1] = (val >> 8) & 0xff;
    upb_sink_putstring(&p->top->sink, sel, output, 2, NULL);
    return true;
  }

badpadding:
  upb_status_seterrf(&p->status,
                     "Incorrect base64 padding for field: %s (%.*s)",
                     upb_fielddef_name(p->top->f),
                     4, ptr);
  upb_env_reporterror(p->env, &p->status);
  return false;
}


/* Accumulate buffer **********************************************************/

/* Functionality for accumulating a buffer.
 *
 * Some parts of the parser need an entire value as a contiguous string.  For
 * example, to look up a member name in a hash table, or to turn a string into
 * a number, the relevant library routines need the input string to be in
 * contiguous memory, even if the value spanned two or more buffers in the
 * input.  These routines handle that.
 *
 * In the common case we can just point to the input buffer to get this
 * contiguous string and avoid any actual copy.  So we optimistically begin
 * this way.  But there are a few cases where we must instead copy into a
 * separate buffer:
 *
 *   1. The string was not contiguous in the input (it spanned buffers).
 *
 *   2. The string included escape sequences that need to be interpreted to get
 *      the true value in a contiguous buffer. */

static void assert_accumulate_empty(upb_json_parser *p) {
  UPB_ASSERT(p->accumulated == NULL);
  UPB_ASSERT(p->accumulated_len == 0);
}

static void accumulate_clear(upb_json_parser *p) {
  p->accumulated = NULL;
  p->accumulated_len = 0;
}

/* Used internally by accumulate_append(). */
static bool accumulate_realloc(upb_json_parser *p, size_t need) {
  void *mem;
  size_t old_size = p->accumulate_buf_size;
  size_t new_size = UPB_MAX(old_size, 128);
  while (new_size < need) {
    new_size = saturating_multiply(new_size, 2);
  }

  mem = upb_env_realloc(p->env, p->accumulate_buf, old_size, new_size);
  if (!mem) {
    upb_status_seterrmsg(&p->status, "Out of memory allocating buffer.");
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  p->accumulate_buf = mem;
  p->accumulate_buf_size = new_size;
  return true;
}

/* Logically appends the given data to the append buffer.
 * If "can_alias" is true, we will try to avoid actually copying, but the buffer
 * must be valid until the next accumulate_append() call (if any). */
static bool accumulate_append(upb_json_parser *p, const char *buf, size_t len,
                              bool can_alias) {
  size_t need;

  if (!p->accumulated && can_alias) {
    p->accumulated = buf;
    p->accumulated_len = len;
    return true;
  }

  if (!checked_add(p->accumulated_len, len, &need)) {
    upb_status_seterrmsg(&p->status, "Integer overflow.");
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  if (need > p->accumulate_buf_size && !accumulate_realloc(p, need)) {
    return false;
  }

  if (p->accumulated != p->accumulate_buf) {
    memcpy(p->accumulate_buf, p->accumulated, p->accumulated_len);
    p->accumulated = p->accumulate_buf;
  }

  memcpy(p->accumulate_buf + p->accumulated_len, buf, len);
  p->accumulated_len += len;
  return true;
}

/* Returns a pointer to the data accumulated since the last accumulate_clear()
 * call, and writes the length to *len.  This with point either to the input
 * buffer or a temporary accumulate buffer. */
static const char *accumulate_getptr(upb_json_parser *p, size_t *len) {
  UPB_ASSERT(p->accumulated);
  *len = p->accumulated_len;
  return p->accumulated;
}


/* Mult-part text data ********************************************************/

/* When we have text data in the input, it can often come in multiple segments.
 * For example, there may be some raw string data followed by an escape
 * sequence.  The two segments are processed with different logic.  Also buffer
 * seams in the input can cause multiple segments.
 *
 * As we see segments, there are two main cases for how we want to process them:
 *
 *  1. we want to push the captured input directly to string handlers.
 *
 *  2. we need to accumulate all the parts into a contiguous buffer for further
 *     processing (field name lookup, string->number conversion, etc). */

/* This is the set of states for p->multipart_state. */
enum {
  /* We are not currently processing multipart data. */
  MULTIPART_INACTIVE = 0,

  /* We are processing multipart data by accumulating it into a contiguous
   * buffer. */
  MULTIPART_ACCUMULATE = 1,

  /* We are processing multipart data by pushing each part directly to the
   * current string handlers. */
  MULTIPART_PUSHEAGERLY = 2
};

/* Start a multi-part text value where we accumulate the data for processing at
 * the end. */
static void multipart_startaccum(upb_json_parser *p) {
  assert_accumulate_empty(p);
  UPB_ASSERT(p->multipart_state == MULTIPART_INACTIVE);
  p->multipart_state = MULTIPART_ACCUMULATE;
}

/* Start a multi-part text value where we immediately push text data to a string
 * value with the given selector. */
static void multipart_start(upb_json_parser *p, upb_selector_t sel) {
  assert_accumulate_empty(p);
  UPB_ASSERT(p->multipart_state == MULTIPART_INACTIVE);
  p->multipart_state = MULTIPART_PUSHEAGERLY;
  p->string_selector = sel;
}

static bool multipart_text(upb_json_parser *p, const char *buf, size_t len,
                           bool can_alias) {
  switch (p->multipart_state) {
    case MULTIPART_INACTIVE:
      upb_status_seterrmsg(
          &p->status, "Internal error: unexpected state MULTIPART_INACTIVE");
      upb_env_reporterror(p->env, &p->status);
      return false;

    case MULTIPART_ACCUMULATE:
      if (!accumulate_append(p, buf, len, can_alias)) {
        return false;
      }
      break;

    case MULTIPART_PUSHEAGERLY: {
      const upb_bufhandle *handle = can_alias ? p->handle : NULL;
      upb_sink_putstring(&p->top->sink, p->string_selector, buf, len, handle);
      break;
    }
  }

  return true;
}

/* Note: this invalidates the accumulate buffer!  Call only after reading its
 * contents. */
static void multipart_end(upb_json_parser *p) {
  UPB_ASSERT(p->multipart_state != MULTIPART_INACTIVE);
  p->multipart_state = MULTIPART_INACTIVE;
  accumulate_clear(p);
}


/* Input capture **************************************************************/

/* Functionality for capturing a region of the input as text.  Gracefully
 * handles the case where a buffer seam occurs in the middle of the captured
 * region. */

static void capture_begin(upb_json_parser *p, const char *ptr) {
  UPB_ASSERT(p->multipart_state != MULTIPART_INACTIVE);
  UPB_ASSERT(p->capture == NULL);
  p->capture = ptr;
}

static bool capture_end(upb_json_parser *p, const char *ptr) {
  UPB_ASSERT(p->capture);
  if (multipart_text(p, p->capture, ptr - p->capture, true)) {
    p->capture = NULL;
    return true;
  } else {
    return false;
  }
}

/* This is called at the end of each input buffer (ie. when we have hit a
 * buffer seam).  If we are in the middle of capturing the input, this
 * processes the unprocessed capture region. */
static void capture_suspend(upb_json_parser *p, const char **ptr) {
  if (!p->capture) return;

  if (multipart_text(p, p->capture, *ptr - p->capture, false)) {
    /* We use this as a signal that we were in the middle of capturing, and
     * that capturing should resume at the beginning of the next buffer.
     * 
     * We can't use *ptr here, because we have no guarantee that this pointer
     * will be valid when we resume (if the underlying memory is freed, then
     * using the pointer at all, even to compare to NULL, is likely undefined
     * behavior). */
    p->capture = &suspend_capture;
  } else {
    /* Need to back up the pointer to the beginning of the capture, since
     * we were not able to actually preserve it. */
    *ptr = p->capture;
  }
}

static void capture_resume(upb_json_parser *p, const char *ptr) {
  if (p->capture) {
    UPB_ASSERT(p->capture == &suspend_capture);
    p->capture = ptr;
  }
}


/* Callbacks from the parser **************************************************/

/* These are the functions called directly from the parser itself.
 * We define these in the same order as their declarations in the parser. */

static char escape_char(char in) {
  switch (in) {
    case 'r': return '\r';
    case 't': return '\t';
    case 'n': return '\n';
    case 'f': return '\f';
    case 'b': return '\b';
    case '/': return '/';
    case '"': return '"';
    case '\\': return '\\';
    default:
      UPB_ASSERT(0);
      return 'x';
  }
}

static bool escape(upb_json_parser *p, const char *ptr) {
  char ch = escape_char(*ptr);
  return multipart_text(p, &ch, 1, false);
}

static void start_hex(upb_json_parser *p) {
  p->digit = 0;
}

static void hexdigit(upb_json_parser *p, const char *ptr) {
  char ch = *ptr;

  p->digit <<= 4;

  if (ch >= '0' && ch <= '9') {
    p->digit += (ch - '0');
  } else if (ch >= 'a' && ch <= 'f') {
    p->digit += ((ch - 'a') + 10);
  } else {
    UPB_ASSERT(ch >= 'A' && ch <= 'F');
    p->digit += ((ch - 'A') + 10);
  }
}

static bool end_hex(upb_json_parser *p) {
  uint32_t codepoint = p->digit;

  /* emit the codepoint as UTF-8. */
  char utf8[3]; /* support \u0000 -- \uFFFF -- need only three bytes. */
  int length = 0;
  if (codepoint <= 0x7F) {
    utf8[0] = codepoint;
    length = 1;
  } else if (codepoint <= 0x07FF) {
    utf8[1] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[0] = (codepoint & 0x1F) | 0xC0;
    length = 2;
  } else /* codepoint <= 0xFFFF */ {
    utf8[2] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[1] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[0] = (codepoint & 0x0F) | 0xE0;
    length = 3;
  }
  /* TODO(haberman): Handle high surrogates: if codepoint is a high surrogate
   * we have to wait for the next escape to get the full code point). */

  return multipart_text(p, utf8, length, false);
}

static void start_text(upb_json_parser *p, const char *ptr) {
  capture_begin(p, ptr);
}

static bool end_text(upb_json_parser *p, const char *ptr) {
  return capture_end(p, ptr);
}

static void start_number(upb_json_parser *p, const char *ptr) {
  multipart_startaccum(p);
  capture_begin(p, ptr);
}

static bool parse_number(upb_json_parser *p, bool is_quoted);

static bool end_number(upb_json_parser *p, const char *ptr) {
  if (!capture_end(p, ptr)) {
    return false;
  }

  if (p->top->f == NULL) {
    multipart_end(p);
    return true;
  }

  return parse_number(p, false);
}

/* |buf| is NULL-terminated. |buf| itself will never include quotes;
 * |is_quoted| tells us whether this text originally appeared inside quotes. */
static bool parse_number_from_buffer(upb_json_parser *p, const char *buf,
                                     bool is_quoted) {
  size_t len = strlen(buf);
  const char *bufend = buf + len;
  char *end;
  upb_fieldtype_t type = upb_fielddef_type(p->top->f);
  double val;
  double dummy;
  double inf = 1.0 / 0.0;  /* C89 does not have an INFINITY macro. */

  errno = 0;

  if (len == 0 || buf[0] == ' ') {
    return false;
  }

  /* For integer types, first try parsing with integer-specific routines.
   * If these succeed, they will be more accurate for int64/uint64 than
   * strtod().
   */
  switch (type) {
    case UPB_TYPE_ENUM:
    case UPB_TYPE_INT32: {
      long val = strtol(buf, &end, 0);
      if (errno == ERANGE || end != bufend) {
        break;
      } else if (val > INT32_MAX || val < INT32_MIN) {
        return false;
      } else {
        upb_sink_putint32(&p->top->sink, parser_getsel(p), val);
        return true;
      }
    }
    case UPB_TYPE_UINT32: {
      unsigned long val = strtoul(buf, &end, 0);
      if (end != bufend) {
        break;
      } else if (val > UINT32_MAX || errno == ERANGE) {
        return false;
      } else {
        upb_sink_putuint32(&p->top->sink, parser_getsel(p), val);
        return true;
      }
    }
    /* XXX: We can't handle [u]int64 properly on 32-bit machines because
     * strto[u]ll isn't in C89. */
    case UPB_TYPE_INT64: {
      long val = strtol(buf, &end, 0);
      if (errno == ERANGE || end != bufend) {
        break;
      } else {
        upb_sink_putint64(&p->top->sink, parser_getsel(p), val);
        return true;
      }
    }
    case UPB_TYPE_UINT64: {
      unsigned long val = strtoul(p->accumulated, &end, 0);
      if (end != bufend) {
        break;
      } else if (errno == ERANGE) {
        return false;
      } else {
        upb_sink_putuint64(&p->top->sink, parser_getsel(p), val);
        return true;
      }
    }
    default:
      break;
  }

  if (type != UPB_TYPE_DOUBLE && type != UPB_TYPE_FLOAT && is_quoted) {
    /* Quoted numbers for integer types are not allowed to be in double form. */
    return false;
  }

  if (len == strlen("Infinity") && strcmp(buf, "Infinity") == 0) {
    /* C89 does not have an INFINITY macro. */
    val = inf;
  } else if (len == strlen("-Infinity") && strcmp(buf, "-Infinity") == 0) {
    val = -inf;
  } else {
    val = strtod(buf, &end);
    if (errno == ERANGE || end != bufend) {
      return false;
    }
  }

  switch (type) {
#define CASE(capitaltype, smalltype, ctype, min, max)                     \
    case UPB_TYPE_ ## capitaltype: {                                      \
      if (modf(val, &dummy) != 0 || val > max || val < min) {             \
        return false;                                                     \
      } else {                                                            \
        upb_sink_put ## smalltype(&p->top->sink, parser_getsel(p),        \
                                  (ctype)val);                            \
        return true;                                                      \
      }                                                                   \
      break;                                                              \
    }
    case UPB_TYPE_ENUM:
    CASE(INT32, int32, int32_t, INT32_MIN, INT32_MAX);
    CASE(INT64, int64, int64_t, INT64_MIN, INT64_MAX);
    CASE(UINT32, uint32, uint32_t, 0, UINT32_MAX);
    CASE(UINT64, uint64, uint64_t, 0, UINT64_MAX);
#undef CASE

    case UPB_TYPE_DOUBLE:
      upb_sink_putdouble(&p->top->sink, parser_getsel(p), val);
      return true;
    case UPB_TYPE_FLOAT:
      if ((val > FLT_MAX || val < -FLT_MAX) && val != inf && val != -inf) {
        return false;
      } else {
        upb_sink_putfloat(&p->top->sink, parser_getsel(p), val);
        return true;
      }
    default:
      return false;
  }
}

static bool parse_number(upb_json_parser *p, bool is_quoted) {
  size_t len;
  const char *buf;

  /* strtol() and friends unfortunately do not support specifying the length of
   * the input string, so we need to force a copy into a NULL-terminated buffer. */
  if (!multipart_text(p, "\0", 1, false)) {
    return false;
  }

  buf = accumulate_getptr(p, &len);

  if (parse_number_from_buffer(p, buf, is_quoted)) {
    multipart_end(p);
    return true;
  } else {
    upb_status_seterrf(&p->status, "error parsing number: %s", buf);
    upb_env_reporterror(p->env, &p->status);
    multipart_end(p);
    return false;
  }
}

static bool parser_putbool(upb_json_parser *p, bool val) {
  bool ok;

  if (p->top->f == NULL) {
    return true;
  }

  if (upb_fielddef_type(p->top->f) != UPB_TYPE_BOOL) {
    upb_status_seterrf(&p->status,
                       "Boolean value specified for non-bool field: %s",
                       upb_fielddef_name(p->top->f));
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  ok = upb_sink_putbool(&p->top->sink, parser_getsel(p), val);
  UPB_ASSERT(ok);

  return true;
}

static bool start_stringval(upb_json_parser *p) {
  if (p->top->f == NULL || p->top->m == p->any_msgdef) {
    /* For unknown field, we still need to start accmulate so that the state
     * machine can work correctly.
     * Any has only two fields: type_url (string) and value (bytes).  For
     * type_url, we need it to figure the type of packed message.  Instead of
     * eargly pushing, we will accumulate it for further usage. */
    multipart_startaccum(p);
    return true;
  }

  if (upb_fielddef_isstring(p->top->f)) {
    upb_jsonparser_frame *inner;
    upb_selector_t sel;

    if (!check_stack(p)) return false;

    /* Start a new parser frame: parser frames correspond one-to-one with
     * handler frames, and string events occur in a sub-frame. */
    inner = p->top + 1;
    sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
    upb_sink_startstr(&p->top->sink, sel, 0, &inner->sink);
    inner->m = p->top->m;
    inner->f = p->top->f;
    inner->name_table = NULL;
    inner->is_map = false;
    inner->is_mapentry = false;
    p->top = inner;

    if (upb_fielddef_type(p->top->f) == UPB_TYPE_STRING) {
      /* For STRING fields we push data directly to the handlers as it is
       * parsed.  We don't do this yet for BYTES fields, because our base64
       * decoder is not streaming.
       *
       * TODO(haberman): make base64 decoding streaming also. */
      multipart_start(p, getsel_for_handlertype(p, UPB_HANDLER_STRING));
      return true;
    } else {
      multipart_startaccum(p);
      return true;
    }
  } else if (upb_fielddef_type(p->top->f) != UPB_TYPE_BOOL &&
             upb_fielddef_type(p->top->f) != UPB_TYPE_MESSAGE) {
    /* No need to push a frame -- numeric values in quotes remain in the
     * current parser frame.  These values must accmulate so we can convert
     * them all at once at the end. */
    multipart_startaccum(p);
    return true;
  } else {
    upb_status_seterrf(&p->status,
                       "String specified for bool or submessage field: %s",
                       upb_fielddef_name(p->top->f));
    upb_env_reporterror(p->env, &p->status);
    return false;
  }
}

static upb_any_jsonparser_frame *new_any_jsonparser_frame(
    upb_json_parser *p) {
  upb_any_jsonparser_frame *frame =
      upb_env_malloc(p->env, sizeof(upb_any_jsonparser_frame));

  frame->any_payload_serialize_handlers =
      upb_pb_encoder_newhandlers(
          p->top->m, &frame->any_payload_serialize_handlers);
  upb_stringsink_init(&frame->sink);
  frame->encoder = upb_pb_encoder_create(
      p->env, frame->any_payload_serialize_handlers, &frame->sink.sink);

  frame->method = p->method;
  p->method = upb_json_parsermethod_new(p->top->m, frame);

  upb_sink_reset(&p->top->sink, frame->any_payload_serialize_handlers,
                 frame->encoder);
  upb_sink_startmsg(&p->top->sink);

  return frame;
}

static bool end_stringval(upb_json_parser *p) {
  bool ok = true;

  if (p->top->f == NULL) {
    multipart_end(p);
    return true;
  }

  switch (upb_fielddef_type(p->top->f)) {
    case UPB_TYPE_BYTES:
      if (!base64_push(p, getsel_for_handlertype(p, UPB_HANDLER_STRING),
                       p->accumulated, p->accumulated_len)) {
        return false;
      }
      /* Fall through. */

    case UPB_TYPE_STRING: {
      if (p->top->m == p->any_msgdef) {
        /* Any's only string field is type_url. */
        size_t len;
        const char *buf = accumulate_getptr(p, &len);

        /* Set type_url. */
        upb_selector_t sel;
        upb_jsonparser_frame *inner;
        if (!check_stack(p)) return false;
        inner = p->top + 1;

        sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
        upb_sink_startstr(&p->top->sink, sel, 0, &inner->sink);
        sel = getsel_for_handlertype(p, UPB_HANDLER_STRING);
        upb_sink_putstring(&inner->sink, sel, buf, len, NULL);
        sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
        upb_sink_endstr(&inner->sink, sel);

        /*  When this frame becomes top again, the parsing is ready to finish. */
        p->top->parse_any_round = PARSE_ANY_FINISH;
        multipart_end(p);

        /* Prepare parser frame for value field. */
        upb_value v;
        bool ok = upb_strtable_lookup2(p->top->name_table, "value", 5, &v);
        UPB_ASSERT(ok);
        p->top->f = upb_value_getconstptr(v);

        inner->parse_any_round = PARSE_ANY_SWITCH;
        inner->f = NULL;
        inner->is_map = false;
        inner->is_mapentry = false;
        inner->any_start = p->top->any_start;
        p->top->any_start = NULL;

        p->top = inner;

        if (strncmp(buf, "type.googleapis.com/", 20) == 0 && len > 20) {
          buf += 20;
          len -= 20;

          if (upb_strtable_lookup2(&p->symbol_table->symtab, buf, len, &v)) {
            p->top->m = upb_value_getptr(v);
            p->top->well_known_type = get_well_known_type(p);

            p->top->any_jsonparser_frame = new_any_jsonparser_frame(p);
            set_name_table(p, p->top);

            return true;
          } else {
            // TODO(teboring): Invalid type url.
            return false;
          }
        } else {
          // TODO(teboring): Invalid type url.
          return false;
        }

      }
      upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
      p->top--;
      upb_sink_endstr(&p->top->sink, sel);
      break;
    }

    case UPB_TYPE_ENUM: {
      /* Resolve enum symbolic name to integer value. */
      const upb_enumdef *enumdef =
          (const upb_enumdef*)upb_fielddef_subdef(p->top->f);

      size_t len;
      const char *buf = accumulate_getptr(p, &len);

      int32_t int_val = 0;
      ok = upb_enumdef_ntoi(enumdef, buf, len, &int_val);

      if (ok) {
        upb_selector_t sel = parser_getsel(p);
        upb_sink_putint32(&p->top->sink, sel, int_val);
      } else {
        upb_status_seterrf(&p->status, "Enum value unknown: '%.*s'", len, buf);
        upb_env_reporterror(p->env, &p->status);
      }

      break;
    }

    case UPB_TYPE_INT32:
    case UPB_TYPE_INT64:
    case UPB_TYPE_UINT32:
    case UPB_TYPE_UINT64:
    case UPB_TYPE_DOUBLE:
    case UPB_TYPE_FLOAT:
      ok = parse_number(p, true);
      break;

    default:
      UPB_ASSERT(false);
      upb_status_seterrmsg(&p->status, "Internal error in JSON decoder");
      upb_env_reporterror(p->env, &p->status);
      ok = false;
      break;
  }

  multipart_end(p);

  return ok;
}

static void start_member(upb_json_parser *p) {
  UPB_ASSERT(!p->top->f);
  multipart_startaccum(p);
}

/* Helper: invoked during parse_mapentry() to emit the mapentry message's key
 * field based on the current contents of the accumulate buffer. */
static bool parse_mapentry_key(upb_json_parser *p) {

  size_t len;
  const char *buf = accumulate_getptr(p, &len);

  /* Emit the key field. We do a bit of ad-hoc parsing here because the
   * parser state machine has already decided that this is a string field
   * name, and we are reinterpreting it as some arbitrary key type. In
   * particular, integer and bool keys are quoted, so we need to parse the
   * quoted string contents here. */

  p->top->f = upb_msgdef_itof(p->top->m, UPB_MAPENTRY_KEY);
  if (p->top->f == NULL) {
    upb_status_seterrmsg(&p->status, "mapentry message has no key");
    upb_env_reporterror(p->env, &p->status);
    return false;
  }
  switch (upb_fielddef_type(p->top->f)) {
    case UPB_TYPE_INT32:
    case UPB_TYPE_INT64:
    case UPB_TYPE_UINT32:
    case UPB_TYPE_UINT64:
      /* Invoke end_number. The accum buffer has the number's text already. */
      if (!parse_number(p, true)) {
        return false;
      }
      break;
    case UPB_TYPE_BOOL:
      if (len == 4 && !strncmp(buf, "true", 4)) {
        if (!parser_putbool(p, true)) {
          return false;
        }
      } else if (len == 5 && !strncmp(buf, "false", 5)) {
        if (!parser_putbool(p, false)) {
          return false;
        }
      } else {
        upb_status_seterrmsg(&p->status,
                             "Map bool key not 'true' or 'false'");
        upb_env_reporterror(p->env, &p->status);
        return false;
      }
      multipart_end(p);
      break;
    case UPB_TYPE_STRING:
    case UPB_TYPE_BYTES: {
      upb_sink subsink;
      upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
      upb_sink_startstr(&p->top->sink, sel, len, &subsink);
      sel = getsel_for_handlertype(p, UPB_HANDLER_STRING);
      upb_sink_putstring(&subsink, sel, buf, len, NULL);
      sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
      upb_sink_endstr(&p->top->sink, sel);
      multipart_end(p);
      break;
    }
    default:
      upb_status_seterrmsg(&p->status, "Invalid field type for map key");
      upb_env_reporterror(p->env, &p->status);
      return false;
  }

  return true;
}

/* Helper: emit one map entry (as a submessage in the map field sequence). This
 * is invoked from end_membername(), at the end of the map entry's key string,
 * with the map key in the accumulate buffer. It parses the key from that
 * buffer, emits the handler calls to start the mapentry submessage (setting up
 * its subframe in the process), and sets up state in the subframe so that the
 * value parser (invoked next) will emit the mapentry's value field and then
 * end the mapentry message. */

static bool handle_mapentry(upb_json_parser *p) {
  const upb_fielddef *mapfield;
  const upb_msgdef *mapentrymsg;
  upb_jsonparser_frame *inner;
  upb_selector_t sel;

  /* Map entry: p->top->sink is the seq frame, so we need to start a frame
   * for the mapentry itself, and then set |f| in that frame so that the map
   * value field is parsed, and also set a flag to end the frame after the
   * map-entry value is parsed. */
  if (!check_stack(p)) return false;

  mapfield = p->top->mapfield;
  mapentrymsg = upb_fielddef_msgsubdef(mapfield);

  inner = p->top + 1;
  p->top->f = mapfield;
  sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSUBMSG);
  upb_sink_startsubmsg(&p->top->sink, sel, &inner->sink);
  inner->m = mapentrymsg;
  inner->name_table = NULL;
  inner->mapfield = mapfield;
  inner->is_map = false;

  /* Don't set this to true *yet* -- we reuse parsing handlers below to push
   * the key field value to the sink, and these handlers will pop the frame
   * if they see is_mapentry (when invoked by the parser state machine, they
   * would have just seen the map-entry value, not key). */
  inner->is_mapentry = false;
  p->top = inner;

  /* send STARTMSG in submsg frame. */
  upb_sink_startmsg(&p->top->sink);

  parse_mapentry_key(p);

  /* Set up the value field to receive the map-entry value. */
  p->top->f = upb_msgdef_itof(p->top->m, UPB_MAPENTRY_VALUE);
  p->top->is_mapentry = true;  /* set up to pop frame after value is parsed. */
  p->top->mapfield = mapfield;
  if (p->top->f == NULL) {
    upb_status_seterrmsg(&p->status, "mapentry message has no value");
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  return true;
}

static bool end_membername(upb_json_parser *p) {
  UPB_ASSERT(!p->top->f);

  if (p->top->is_map) {
    return handle_mapentry(p);
  } else {
    if (p->top->m == NULL) {
      multipart_end(p);
      return true;
    }

    size_t len;
    const char *buf = accumulate_getptr(p, &len);
    upb_value v;

    if (upb_strtable_lookup2(p->top->name_table, buf, len, &v)) {
      p->top->f = upb_value_getconstptr(v);
      multipart_end(p);

      return true;
    } else {
      /* type_url field of Any is not unknown. */
      if (!check_stack_start(p)) {
        upb_jsonparser_frame *parent;
        parent = p->top - 1;
        if (parent->m == p->any_msgdef && !strncmp(buf, "@type", 5) &&
            len == 5) {
          multipart_end(p);
          return true;
        }
      }
      /* TODO(haberman): Ignore unknown fields if requested/configured to do
       * so. */
      upb_status_seterrf(&p->status, "No such field: %.*s\n", (int)len, buf);
      upb_env_reporterror(p->env, &p->status);
      return false;
    }
  }
}

static void end_member(upb_json_parser *p) {
  /* If we just parsed a map-entry value, end that frame too. */
  if (p->top->is_mapentry) {
    upb_status s = UPB_STATUS_INIT;
    upb_selector_t sel;
    bool ok;
    const upb_fielddef *mapfield;

    UPB_ASSERT(p->top > p->stack);
    /* send ENDMSG on submsg. */
    upb_sink_endmsg(&p->top->sink, &s);
    mapfield = p->top->mapfield;

    /* send ENDSUBMSG in repeated-field-of-mapentries frame. */
    p->top--;
    ok = upb_handlers_getselector(mapfield, UPB_HANDLER_ENDSUBMSG, &sel);
    UPB_ASSERT(ok);
    upb_sink_endsubmsg(&p->top->sink, sel);
  }

  p->top->f = NULL;
}

/* At the first time entering any_machine, the current buffer position is
 * recorded as the start point. When type_url is found, we will go back to
 * the start point and run any_machine again with the found type_url.*/
static void start_any(upb_json_parser *p, const char *any_start) {
  p->top->any_start = any_start;
  p->top->parse_any_round = PARSE_ANY_ROUND1;
}

static const char* end_any_round1(upb_json_parser *p) {
  p->top->parse_any_round = PARSE_ANY_ROUND2;
  const char *any_start = p->top->any_start;
  p->top->any_start = NULL;
  return any_start;
}

static void end_any_round2(upb_json_parser *p) {
  char *buf = p->top->any_jsonparser_frame->sink.ptr;
  int len = p->top->any_jsonparser_frame->sink.len;

  upb_jsonparser_frame *inner = p->top;
  p->top--;

  upb_selector_t sel;

  sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
  upb_sink_startstr(&p->top->sink, sel, 0, &inner->sink);
  sel = getsel_for_handlertype(p, UPB_HANDLER_STRING);
  upb_sink_putstring(&inner->sink, sel, buf, len, NULL);
  sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
  upb_sink_endstr(&inner->sink, sel);
}

static int end_normal_machine(upb_json_parser *p) {
  if (check_stack_start(p)) {
    return WELL_KNOWN_NORMAL;
  }

  if (p->top->m == NULL) {
    return WELL_KNOWN_NORMAL;
  }

  upb_jsonparser_frame *parent = p->top - 1;
  if (parent->m == p->any_msgdef) {
    return WELL_KNOWN_ANY;
  } else {
    return WELL_KNOWN_NORMAL;
  }
}

static void start_any_member(upb_json_parser *p) {
  multipart_startaccum(p);
}

static bool end_any_membername(upb_json_parser *p) {
  UPB_ASSERT(!p->top->f);

  size_t len;
  const char *buf = accumulate_getptr(p, &len);
  upb_value v;
  bool ok;

  switch (p->top->parse_any_round) {
  case PARSE_ANY_ROUND1: {
    if (strncmp(buf, "@type", 5) == 0 && len == 5) {
      ok = upb_strtable_lookup2(p->top->name_table, "type_url", 8, &v);
      UPB_ASSERT(ok);
      p->top->f = upb_value_getconstptr(v);
    }
    break;
  }
  case PARSE_ANY_ROUND2: {
    if (len != 5 || strncmp(buf, "@type", 5) != 0) {
      ok = upb_strtable_lookup2(p->top->name_table, buf, len, &v);
      if (ok) {
        p->top->f = upb_value_getconstptr(v);
      }
    }
    break;
  }
  default:
    break;
  }

  multipart_end(p);
  return true;
}

static int any_round1_finished(upb_json_parser *p) {
  return p->top->parse_any_round == PARSE_ANY_SWITCH;
}

static int end_any_member(upb_json_parser *p, const char **buf) {
  if (p->top->parse_any_round == PARSE_ANY_SWITCH) {
    *buf = p->top->any_start;
    p->top->any_start = NULL;
    return p->top->well_known_type;
  } else {
    return -1;
  }
}

static bool start_subobject(upb_json_parser *p) {
  if (p->top->f == NULL) {
    upb_jsonparser_frame *inner;

    /* Beginning of a subobject. Start a new parser frame in the submsg
     * context. */
    if (!check_stack(p)) return false;

    inner = p->top + 1;

    inner->sink.handlers = NULL;
    inner->m = NULL;
    inner->f = NULL;
    inner->is_map = false;
    inner->is_mapentry = false;
    inner->well_known_type = WELL_KNOWN_NORMAL;

    p->top = inner;
    return true;
  }

  if (upb_fielddef_ismap(p->top->f)) {
    upb_jsonparser_frame *inner;
    upb_selector_t sel;

    /* Beginning of a map. Start a new parser frame in a repeated-field
     * context. */
    if (!check_stack(p)) return false;

    inner = p->top + 1;
    sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSEQ);
    upb_sink_startseq(&p->top->sink, sel, &inner->sink);
    inner->m = upb_fielddef_msgsubdef(p->top->f);
    inner->name_table = NULL;
    inner->mapfield = p->top->f;
    inner->f = NULL;
    inner->is_map = true;
    inner->is_mapentry = false;
    // inner->parse_any_round = PARSE_ANY_NOT_STARTED;
    if (inner->m == p->any_msgdef) {
      inner->well_known_type = WELL_KNOWN_ANY;
    } else {
      inner->well_known_type = WELL_KNOWN_NORMAL;
    }
    p->top = inner;

    return true;
  } else if (upb_fielddef_issubmsg(p->top->f)) {
    upb_jsonparser_frame *inner;
    upb_selector_t sel;

    /* Beginning of a subobject. Start a new parser frame in the submsg
     * context. */
    if (!check_stack(p)) return false;

    inner = p->top + 1;

    sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSUBMSG);
    upb_sink_startsubmsg(&p->top->sink, sel, &inner->sink);
    inner->m = upb_fielddef_msgsubdef(p->top->f);
    set_name_table(p, inner);
    inner->f = NULL;
    inner->is_map = false;
    inner->is_mapentry = false;
    inner->parse_any_round = PARSE_ANY_NOT_STARTED;
    if (inner->m == p->any_msgdef) {
      inner->well_known_type = WELL_KNOWN_ANY;
    } else {
      inner->well_known_type = WELL_KNOWN_NORMAL;
    }
    p->top = inner;

    return true;
  } else {
    upb_status_seterrf(&p->status,
                       "Object specified for non-message/group field: %s",
                       upb_fielddef_name(p->top->f));
    upb_env_reporterror(p->env, &p->status);
    return false;
  }
}

static void end_subobject(upb_json_parser *p) {
  if (p->top->is_map) {
    upb_selector_t sel;
    p->top--;
    sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSEQ);
    upb_sink_endseq(&p->top->sink, sel);
  } else {
    upb_selector_t sel;
    p->top--;
    if (p->top->f != NULL) {
      sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSUBMSG);
      upb_sink_endsubmsg(&p->top->sink, sel);
    }
  }
}

static bool start_array(upb_json_parser *p) {
  upb_jsonparser_frame *inner;
  upb_selector_t sel;

  if (p->top->f == NULL) {
    if (!check_stack(p)) return false;

    inner = p->top + 1;

    inner->sink.handlers = NULL;
    inner->m = NULL;
    inner->f = NULL;
    inner->is_map = false;
    inner->is_mapentry = false;
    inner->well_known_type = WELL_KNOWN_NORMAL;

    p->top = inner;
    return true;
  }

  if (!upb_fielddef_isseq(p->top->f)) {
    upb_status_seterrf(&p->status,
                       "Array specified for non-repeated field: %s",
                       upb_fielddef_name(p->top->f));
    upb_env_reporterror(p->env, &p->status);
    return false;
  }

  if (!check_stack(p)) return false;

  inner = p->top + 1;
  sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSEQ);
  upb_sink_startseq(&p->top->sink, sel, &inner->sink);
  inner->m = p->top->m;
  inner->name_table = NULL;
  inner->f = p->top->f;
  inner->is_map = false;
  inner->is_mapentry = false;
  p->top = inner;

  return true;
}

static void end_array(upb_json_parser *p) {
  upb_selector_t sel;

  UPB_ASSERT(p->top > p->stack);

  p->top--;
  if (p->top->f != NULL) {
    sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSEQ);
    upb_sink_endseq(&p->top->sink, sel);
  }
}

static void start_object(upb_json_parser *p) {
  if (!p->top->is_map) {
    upb_sink_startmsg(&p->top->sink);
  }
}

static void end_object(upb_json_parser *p) {
  if (!p->top->is_map) {
    upb_status status;
    upb_status_clear(&status);
    upb_sink_endmsg(&p->top->sink, &status);
    if (!upb_ok(&status)) {
      upb_env_reporterror(p->env, &status);
    }
  }
}


#define CHECK_RETURN_TOP(x) if (!(x)) goto error


/* The actual parser **********************************************************/

/* What follows is the Ragel parser itself.  The language is specified in Ragel
 * and the actions call our C functions above.
 *
 * Ragel has an extensive set of functionality, and we use only a small part of
 * it.  There are many action types but we only use a few:
 *
 *   ">" -- transition into a machine
 *   "%" -- transition out of a machine
 *   "@" -- transition into a final state of a machine.
 *
 * "@" transitions are tricky because a machine can transition into a final
 * state repeatedly.  But in some cases we know this can't happen, for example
 * a string which is delimited by a final '"' can only transition into its
 * final state once, when the closing '"' is seen. */


#line 1783 "upb/json/parser.rl"



#line 1608 "upb/json/parser.c"
static const char _json_actions[] = {
	0, 1, 0, 1, 2, 1, 3, 1, 
	5, 1, 6, 1, 7, 1, 8, 1, 
	10, 1, 12, 1, 13, 1, 15, 1, 
	16, 1, 17, 1, 18, 1, 19, 1, 
	20, 1, 21, 1, 22, 1, 26, 1, 
	30, 1, 32, 1, 34, 1, 35, 2, 
	3, 8, 2, 4, 5, 2, 6, 2, 
	2, 6, 8, 2, 11, 9, 2, 13, 
	18, 2, 14, 9, 2, 16, 17, 2, 
	23, 1, 2, 24, 32, 2, 25, 9, 
	2, 27, 32, 2, 28, 32, 2, 29, 
	32, 2, 31, 32, 2, 33, 9
};

static const int json_start = 1;

static const int json_en_number_machine = 4;
static const int json_en_string_machine = 13;
static const int json_en_any_machine = 21;
static const int json_en_any_machine_any_machine_end = 28;
static const int json_en_normal_machine = 29;
static const int json_en_value_machine = 36;
static const int json_en_well_known_type_machine = 59;
static const int json_en_main = 1;


#line 1786 "upb/json/parser.rl"

size_t parse(void *closure, const void *hd, const char *buf, size_t size,
             const upb_bufhandle *handle) {
  upb_json_parser *parser = closure;

  /* Variables used by Ragel's generated code. */
  int cs = parser->current_state;
  int *stack = parser->parser_stack;
  int top = parser->parser_top;

  const char *p = buf;
  const char *pe = buf + size;
  const char *eof = pe;

  parser->handle = handle;

  UPB_UNUSED(hd);
  UPB_UNUSED(handle);

  capture_resume(parser, buf);

  
#line 1659 "upb/json/parser.c"
	{
	const char *_acts;
	unsigned int _nacts;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	switch ( cs ) {
case 1:
	switch( (*p) ) {
		case 32: goto tr0;
		case 123: goto tr2;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr0;
	goto tr1;
case 0:
	goto _out;
case 2:
	switch( (*p) ) {
		case 32: goto tr2;
		case 34: goto tr3;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr2;
	goto tr1;
case 3:
	if ( (*p) == 125 )
		goto tr4;
	goto tr1;
case 80:
	if ( (*p) == 32 )
		goto tr106;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr106;
	goto tr1;
case 4:
	switch( (*p) ) {
		case 45: goto tr5;
		case 48: goto tr6;
	}
	if ( 49 <= (*p) && (*p) <= 57 )
		goto tr7;
	goto tr1;
case 5:
	if ( (*p) == 48 )
		goto tr6;
	if ( 49 <= (*p) && (*p) <= 57 )
		goto tr7;
	goto tr1;
case 6:
	switch( (*p) ) {
		case 46: goto tr9;
		case 69: goto tr10;
		case 101: goto tr10;
	}
	goto tr8;
case 81:
	goto tr1;
case 7:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr11;
	goto tr1;
case 8:
	switch( (*p) ) {
		case 69: goto tr10;
		case 101: goto tr10;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr11;
	goto tr8;
case 9:
	switch( (*p) ) {
		case 43: goto tr12;
		case 45: goto tr12;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr13;
	goto tr1;
case 10:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr13;
	goto tr1;
case 11:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr13;
	goto tr8;
case 12:
	switch( (*p) ) {
		case 46: goto tr9;
		case 69: goto tr10;
		case 101: goto tr10;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr7;
	goto tr8;
case 13:
	switch( (*p) ) {
		case 34: goto tr15;
		case 92: goto tr16;
	}
	goto tr14;
case 14:
	switch( (*p) ) {
		case 34: goto tr18;
		case 92: goto tr19;
	}
	goto tr17;
case 82:
	goto tr1;
case 15:
	switch( (*p) ) {
		case 34: goto tr20;
		case 47: goto tr20;
		case 92: goto tr20;
		case 98: goto tr20;
		case 102: goto tr20;
		case 110: goto tr20;
		case 114: goto tr20;
		case 116: goto tr20;
		case 117: goto tr21;
	}
	goto tr1;
case 16:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr22;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr22;
	} else
		goto tr22;
	goto tr1;
case 17:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr23;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr23;
	} else
		goto tr23;
	goto tr1;
case 18:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr24;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr24;
	} else
		goto tr24;
	goto tr1;
case 19:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr25;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr25;
	} else
		goto tr25;
	goto tr1;
case 20:
	switch( (*p) ) {
		case 34: goto tr27;
		case 92: goto tr28;
	}
	goto tr26;
case 21:
	switch( (*p) ) {
		case 32: goto tr29;
		case 34: goto tr30;
		case 125: goto tr31;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr29;
	goto tr1;
case 22:
	switch( (*p) ) {
		case 32: goto tr29;
		case 34: goto tr30;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr29;
	goto tr1;
case 23:
	if ( (*p) == 34 )
		goto tr32;
	goto tr1;
case 24:
	switch( (*p) ) {
		case 32: goto tr33;
		case 58: goto tr34;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr33;
	goto tr1;
case 25:
	switch( (*p) ) {
		case 32: goto tr34;
		case 93: goto tr1;
		case 125: goto tr1;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr34;
	goto tr35;
case 26:
	switch( (*p) ) {
		case 32: goto tr36;
		case 44: goto tr37;
		case 125: goto tr38;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr36;
	goto tr1;
case 27:
	switch( (*p) ) {
		case 32: goto tr39;
		case 44: goto tr29;
		case 125: goto tr31;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr39;
	goto tr1;
case 83:
	goto tr1;
case 28:
	if ( (*p) == 125 )
		goto tr31;
	goto tr1;
case 29:
	switch( (*p) ) {
		case 32: goto tr40;
		case 34: goto tr41;
		case 125: goto tr42;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr40;
	goto tr1;
case 30:
	switch( (*p) ) {
		case 32: goto tr40;
		case 34: goto tr41;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr40;
	goto tr1;
case 31:
	if ( (*p) == 34 )
		goto tr43;
	goto tr1;
case 32:
	switch( (*p) ) {
		case 32: goto tr44;
		case 58: goto tr45;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr44;
	goto tr1;
case 33:
	switch( (*p) ) {
		case 32: goto tr45;
		case 93: goto tr1;
		case 125: goto tr1;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr45;
	goto tr46;
case 34:
	switch( (*p) ) {
		case 32: goto tr47;
		case 44: goto tr48;
		case 125: goto tr49;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr47;
	goto tr1;
case 35:
	switch( (*p) ) {
		case 32: goto tr50;
		case 44: goto tr40;
		case 125: goto tr42;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr50;
	goto tr1;
case 84:
	goto tr1;
case 36:
	switch( (*p) ) {
		case 34: goto tr51;
		case 45: goto tr52;
		case 91: goto tr53;
		case 102: goto tr54;
		case 110: goto tr55;
		case 116: goto tr56;
		case 123: goto tr57;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr52;
	goto tr1;
case 37:
	if ( (*p) == 34 )
		goto tr58;
	goto tr1;
case 38:
	goto tr59;
case 85:
	goto tr1;
case 39:
	goto tr60;
case 40:
	switch( (*p) ) {
		case 32: goto tr62;
		case 93: goto tr63;
		case 125: goto tr1;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr62;
	goto tr61;
case 41:
	switch( (*p) ) {
		case 32: goto tr64;
		case 44: goto tr65;
		case 93: goto tr63;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr64;
	goto tr1;
case 42:
	switch( (*p) ) {
		case 32: goto tr65;
		case 93: goto tr1;
		case 125: goto tr1;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr65;
	goto tr61;
case 43:
	if ( (*p) == 97 )
		goto tr66;
	goto tr1;
case 44:
	if ( (*p) == 108 )
		goto tr67;
	goto tr1;
case 45:
	if ( (*p) == 115 )
		goto tr68;
	goto tr1;
case 46:
	if ( (*p) == 101 )
		goto tr69;
	goto tr1;
case 47:
	goto tr70;
case 48:
	if ( (*p) == 117 )
		goto tr71;
	goto tr1;
case 49:
	if ( (*p) == 108 )
		goto tr72;
	goto tr1;
case 50:
	if ( (*p) == 108 )
		goto tr73;
	goto tr1;
case 51:
	goto tr74;
case 52:
	if ( (*p) == 114 )
		goto tr75;
	goto tr1;
case 53:
	if ( (*p) == 117 )
		goto tr76;
	goto tr1;
case 54:
	if ( (*p) == 101 )
		goto tr77;
	goto tr1;
case 55:
	goto tr78;
case 56:
	switch( (*p) ) {
		case 32: goto tr79;
		case 34: goto tr80;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr79;
	goto tr1;
case 57:
	if ( (*p) == 125 )
		goto tr81;
	goto tr1;
case 58:
	goto tr82;
case 59:
	switch( (*p) ) {
		case 32: goto tr83;
		case 34: goto tr84;
		case 125: goto tr85;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr83;
	goto tr1;
case 60:
	switch( (*p) ) {
		case 32: goto tr83;
		case 34: goto tr84;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr83;
	goto tr1;
case 61:
	switch( (*p) ) {
		case 64: goto tr86;
		case 118: goto tr87;
	}
	goto tr1;
case 62:
	if ( (*p) == 116 )
		goto tr88;
	goto tr1;
case 63:
	if ( (*p) == 121 )
		goto tr89;
	goto tr1;
case 64:
	if ( (*p) == 112 )
		goto tr90;
	goto tr1;
case 65:
	if ( (*p) == 101 )
		goto tr91;
	goto tr1;
case 66:
	if ( (*p) == 34 )
		goto tr92;
	goto tr1;
case 67:
	switch( (*p) ) {
		case 32: goto tr92;
		case 58: goto tr93;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr92;
	goto tr1;
case 68:
	switch( (*p) ) {
		case 32: goto tr93;
		case 34: goto tr94;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr93;
	goto tr1;
case 69:
	if ( (*p) == 34 )
		goto tr95;
	goto tr1;
case 70:
	switch( (*p) ) {
		case 32: goto tr96;
		case 44: goto tr83;
		case 125: goto tr85;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr96;
	goto tr1;
case 86:
	goto tr1;
case 71:
	if ( (*p) == 97 )
		goto tr97;
	goto tr1;
case 72:
	if ( (*p) == 108 )
		goto tr98;
	goto tr1;
case 73:
	if ( (*p) == 117 )
		goto tr99;
	goto tr1;
case 74:
	if ( (*p) == 101 )
		goto tr100;
	goto tr1;
case 75:
	if ( (*p) == 34 )
		goto tr101;
	goto tr1;
case 76:
	switch( (*p) ) {
		case 32: goto tr101;
		case 58: goto tr102;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr101;
	goto tr1;
case 77:
	switch( (*p) ) {
		case 32: goto tr102;
		case 123: goto tr103;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr102;
	goto tr1;
case 78:
	switch( (*p) ) {
		case 32: goto tr103;
		case 34: goto tr104;
	}
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr103;
	goto tr1;
case 79:
	if ( (*p) == 125 )
		goto tr105;
	goto tr1;
	}

	tr1: cs = 0; goto _again;
	tr0: cs = 1; goto _again;
	tr2: cs = 2; goto _again;
	tr3: cs = 3; goto f0;
	tr5: cs = 5; goto _again;
	tr6: cs = 6; goto _again;
	tr9: cs = 7; goto _again;
	tr11: cs = 8; goto _again;
	tr10: cs = 9; goto _again;
	tr12: cs = 10; goto _again;
	tr13: cs = 11; goto _again;
	tr7: cs = 12; goto _again;
	tr20: cs = 13; goto f7;
	tr17: cs = 14; goto _again;
	tr14: cs = 14; goto f3;
	tr26: cs = 14; goto f10;
	tr16: cs = 15; goto _again;
	tr19: cs = 15; goto f6;
	tr28: cs = 15; goto f12;
	tr21: cs = 16; goto _again;
	tr22: cs = 17; goto f8;
	tr23: cs = 18; goto f9;
	tr24: cs = 19; goto f9;
	tr25: cs = 20; goto f9;
	tr29: cs = 22; goto _again;
	tr37: cs = 22; goto f17;
	tr30: cs = 23; goto f13;
	tr33: cs = 24; goto _again;
	tr32: cs = 24; goto f15;
	tr34: cs = 25; goto _again;
	tr35: cs = 26; goto f16;
	tr39: cs = 27; goto _again;
	tr36: cs = 27; goto f17;
	tr40: cs = 30; goto _again;
	tr48: cs = 30; goto f22;
	tr41: cs = 31; goto f19;
	tr44: cs = 32; goto _again;
	tr43: cs = 32; goto f21;
	tr45: cs = 33; goto _again;
	tr46: cs = 34; goto f16;
	tr50: cs = 35; goto _again;
	tr47: cs = 35; goto f22;
	tr51: cs = 37; goto f24;
	tr58: cs = 38; goto f28;
	tr63: cs = 38; goto f31;
	tr52: cs = 39; goto f25;
	tr62: cs = 40; goto _again;
	tr53: cs = 40; goto f26;
	tr64: cs = 41; goto _again;
	tr61: cs = 41; goto f16;
	tr65: cs = 42; goto _again;
	tr54: cs = 43; goto _again;
	tr66: cs = 44; goto _again;
	tr67: cs = 45; goto _again;
	tr68: cs = 46; goto _again;
	tr69: cs = 47; goto _again;
	tr55: cs = 48; goto _again;
	tr71: cs = 49; goto _again;
	tr72: cs = 50; goto _again;
	tr73: cs = 51; goto _again;
	tr56: cs = 52; goto _again;
	tr75: cs = 53; goto _again;
	tr76: cs = 54; goto _again;
	tr77: cs = 55; goto _again;
	tr79: cs = 56; goto _again;
	tr57: cs = 56; goto f27;
	tr80: cs = 57; goto f0;
	tr81: cs = 58; goto f1;
	tr83: cs = 60; goto _again;
	tr84: cs = 61; goto _again;
	tr86: cs = 62; goto _again;
	tr88: cs = 63; goto _again;
	tr89: cs = 64; goto _again;
	tr90: cs = 65; goto _again;
	tr91: cs = 66; goto _again;
	tr92: cs = 67; goto _again;
	tr93: cs = 68; goto _again;
	tr94: cs = 69; goto f37;
	tr96: cs = 70; goto _again;
	tr105: cs = 70; goto f1;
	tr95: cs = 70; goto f38;
	tr87: cs = 71; goto _again;
	tr97: cs = 72; goto _again;
	tr98: cs = 73; goto _again;
	tr99: cs = 74; goto _again;
	tr100: cs = 75; goto _again;
	tr101: cs = 76; goto _again;
	tr102: cs = 77; goto _again;
	tr103: cs = 78; goto _again;
	tr104: cs = 79; goto f0;
	tr106: cs = 80; goto _again;
	tr4: cs = 80; goto f1;
	tr8: cs = 81; goto f2;
	tr15: cs = 82; goto f4;
	tr18: cs = 82; goto f5;
	tr27: cs = 82; goto f11;
	tr31: cs = 83; goto f14;
	tr38: cs = 83; goto f18;
	tr42: cs = 84; goto f20;
	tr49: cs = 84; goto f23;
	tr59: cs = 85; goto f29;
	tr60: cs = 85; goto f30;
	tr70: cs = 85; goto f32;
	tr74: cs = 85; goto f33;
	tr78: cs = 85; goto f34;
	tr82: cs = 85; goto f35;
	tr85: cs = 86; goto f36;

	f2: _acts = _json_actions + 1; goto execFuncs;
	f3: _acts = _json_actions + 3; goto execFuncs;
	f6: _acts = _json_actions + 5; goto execFuncs;
	f9: _acts = _json_actions + 7; goto execFuncs;
	f12: _acts = _json_actions + 9; goto execFuncs;
	f7: _acts = _json_actions + 11; goto execFuncs;
	f4: _acts = _json_actions + 13; goto execFuncs;
	f16: _acts = _json_actions + 15; goto execFuncs;
	f21: _acts = _json_actions + 17; goto execFuncs;
	f22: _acts = _json_actions + 19; goto execFuncs;
	f15: _acts = _json_actions + 21; goto execFuncs;
	f17: _acts = _json_actions + 23; goto execFuncs;
	f14: _acts = _json_actions + 25; goto execFuncs;
	f20: _acts = _json_actions + 27; goto execFuncs;
	f0: _acts = _json_actions + 29; goto execFuncs;
	f1: _acts = _json_actions + 31; goto execFuncs;
	f26: _acts = _json_actions + 33; goto execFuncs;
	f31: _acts = _json_actions + 35; goto execFuncs;
	f28: _acts = _json_actions + 37; goto execFuncs;
	f27: _acts = _json_actions + 39; goto execFuncs;
	f29: _acts = _json_actions + 41; goto execFuncs;
	f38: _acts = _json_actions + 43; goto execFuncs;
	f36: _acts = _json_actions + 45; goto execFuncs;
	f5: _acts = _json_actions + 47; goto execFuncs;
	f8: _acts = _json_actions + 50; goto execFuncs;
	f10: _acts = _json_actions + 53; goto execFuncs;
	f11: _acts = _json_actions + 56; goto execFuncs;
	f19: _acts = _json_actions + 59; goto execFuncs;
	f23: _acts = _json_actions + 62; goto execFuncs;
	f13: _acts = _json_actions + 65; goto execFuncs;
	f18: _acts = _json_actions + 68; goto execFuncs;
	f25: _acts = _json_actions + 71; goto execFuncs;
	f30: _acts = _json_actions + 74; goto execFuncs;
	f24: _acts = _json_actions + 77; goto execFuncs;
	f34: _acts = _json_actions + 80; goto execFuncs;
	f32: _acts = _json_actions + 83; goto execFuncs;
	f33: _acts = _json_actions + 86; goto execFuncs;
	f35: _acts = _json_actions + 89; goto execFuncs;
	f37: _acts = _json_actions + 92; goto execFuncs;

execFuncs:
	_nacts = *_acts++;
	while ( _nacts-- > 0 ) {
		switch ( *_acts++ ) {
	case 0:
#line 1611 "upb/json/parser.rl"
	{ p--; {cs = stack[--top];goto _again;} }
	break;
	case 1:
#line 1612 "upb/json/parser.rl"
	{ p--; {stack[top++] = cs; cs = 4; goto _again;} }
	break;
	case 2:
#line 1616 "upb/json/parser.rl"
	{ start_text(parser, p); }
	break;
	case 3:
#line 1617 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_text(parser, p)); }
	break;
	case 4:
#line 1623 "upb/json/parser.rl"
	{ start_hex(parser); }
	break;
	case 5:
#line 1624 "upb/json/parser.rl"
	{ hexdigit(parser, p); }
	break;
	case 6:
#line 1625 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_hex(parser)); }
	break;
	case 7:
#line 1631 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(escape(parser, p)); }
	break;
	case 8:
#line 1637 "upb/json/parser.rl"
	{ p--; {cs = stack[--top];goto _again;} }
	break;
	case 9:
#line 1640 "upb/json/parser.rl"
	{ {stack[top++] = cs; cs = 13; goto _again;} }
	break;
	case 10:
#line 1642 "upb/json/parser.rl"
	{ p--; {stack[top++] = cs; cs = 36; goto _again;} }
	break;
	case 11:
#line 1647 "upb/json/parser.rl"
	{ start_member(parser); }
	break;
	case 12:
#line 1648 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_membername(parser)); }
	break;
	case 13:
#line 1651 "upb/json/parser.rl"
	{ end_member(parser); }
	break;
	case 14:
#line 1657 "upb/json/parser.rl"
	{ start_any_member(parser); }
	break;
	case 15:
#line 1658 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_any_membername(parser)); }
	break;
	case 16:
#line 1661 "upb/json/parser.rl"
	{
        switch (end_any_member(parser, &p)) {
        case WELL_KNOWN_ANY:
          {cs = 59; goto _again;}
        case WELL_KNOWN_NORMAL:
          {cs = 29; goto _again;}
        default:
          break;
        }
      }
	break;
	case 17:
#line 1676 "upb/json/parser.rl"
	{
        end_any_round2(parser);
        p--;
        {cs = stack[--top];goto _again;}
      }
	break;
	case 18:
#line 1687 "upb/json/parser.rl"
	{
        p--;
        switch (end_normal_machine(parser)) {
        case WELL_KNOWN_ANY:
          {cs = 28; goto _again;}
        case WELL_KNOWN_NORMAL:
          {cs = stack[--top];goto _again;}
        }
      }
	break;
	case 19:
#line 1698 "upb/json/parser.rl"
	{
          start_object(parser);
          p--;
          switch (parser->top->well_known_type) {
          case WELL_KNOWN_NORMAL: {
            {stack[top++] = cs; cs = 29; goto _again;}
            break;
          }
          case WELL_KNOWN_ANY: {
            start_any(parser, p);
            {stack[top++] = cs; cs = 21; goto _again;}
            break;
          }
          default:
            break;
          }
        }
	break;
	case 20:
#line 1720 "upb/json/parser.rl"
	{ end_object(parser); }
	break;
	case 21:
#line 1726 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(start_array(parser)); }
	break;
	case 22:
#line 1730 "upb/json/parser.rl"
	{ end_array(parser); }
	break;
	case 23:
#line 1735 "upb/json/parser.rl"
	{ start_number(parser, p); }
	break;
	case 24:
#line 1736 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_number(parser, p)); }
	break;
	case 25:
#line 1738 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(start_stringval(parser)); }
	break;
	case 26:
#line 1739 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(end_stringval(parser)); }
	break;
	case 27:
#line 1741 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(parser_putbool(parser, true)); }
	break;
	case 28:
#line 1743 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(parser_putbool(parser, false)); }
	break;
	case 29:
#line 1745 "upb/json/parser.rl"
	{ /* null value */ }
	break;
	case 30:
#line 1747 "upb/json/parser.rl"
	{ CHECK_RETURN_TOP(start_subobject(parser)); }
	break;
	case 31:
#line 1748 "upb/json/parser.rl"
	{ end_subobject(parser); }
	break;
	case 32:
#line 1753 "upb/json/parser.rl"
	{ p--; {cs = stack[--top];goto _again;} }
	break;
	case 33:
#line 1760 "upb/json/parser.rl"
	{ multipart_startaccum(parser); }
	break;
	case 34:
#line 1761 "upb/json/parser.rl"
	{ multipart_end(parser); }
	break;
	case 35:
#line 1779 "upb/json/parser.rl"
	{ p--; {cs = 28; goto _again;} }
	break;
#line 2518 "upb/json/parser.c"
		}
	}
	goto _again;

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 1808 "upb/json/parser.rl"

  if (p != pe) {
    upb_status_seterrf(&parser->status, "Parse error at '%.*s'\n", pe - p, p);
    upb_env_reporterror(parser->env, &parser->status);
  } else {
    capture_suspend(parser, &p);
  }

error:
  /* Save parsing state back to parser. */
  parser->current_state = cs;
  parser->parser_top = top;

  return p - buf;
}

bool end(void *closure, const void *hd) {
  UPB_UNUSED(closure);
  UPB_UNUSED(hd);

  /* Prevent compile warning on unused static constants. */
  UPB_UNUSED(json_start);
  UPB_UNUSED(json_en_number_machine);
  UPB_UNUSED(json_en_string_machine);
  UPB_UNUSED(json_en_value_machine);
  UPB_UNUSED(json_en_main);
  return true;
}

static void json_parser_reset(upb_json_parser *p) {
  int cs;
  int top;

  p->top = p->stack;
  p->top->f = NULL;
  p->top->is_map = false;
  p->top->is_mapentry = false;

  /* Emit Ragel initialization of the parser. */
  
#line 2573 "upb/json/parser.c"
	{
	cs = json_start;
	top = 0;
	}

#line 1848 "upb/json/parser.rl"
  p->current_state = cs;
  p->parser_top = top;
  accumulate_clear(p);
  p->multipart_state = MULTIPART_INACTIVE;
  p->capture = NULL;
  p->accumulated = NULL;
  upb_status_clear(&p->status);
}

static void visit_json_parsermethod(const upb_refcounted *r,
                                    upb_refcounted_visit *visit,
                                    void *closure) {
  const upb_json_parsermethod *method = (upb_json_parsermethod*)r;
  visit(r, upb_msgdef_upcast2(method->msg), closure);
}

static void free_json_parsermethod(upb_refcounted *r) {
  upb_json_parsermethod *method = (upb_json_parsermethod*)r;

  upb_inttable_iter i;
  upb_inttable_begin(&i, &method->name_tables);
  for(; !upb_inttable_done(&i); upb_inttable_next(&i)) {
    upb_value val = upb_inttable_iter_value(&i);
    upb_strtable *t = upb_value_getptr(val);
    upb_strtable_uninit(t);
    upb_gfree(t);
  }

  upb_inttable_uninit(&method->name_tables);

  upb_gfree(r);
}

static void add_jsonname_table(upb_json_parsermethod *m, const upb_msgdef* md) {
  upb_msg_field_iter i;
  upb_strtable *t;

  /* It would be nice to stack-allocate this, but protobufs do not limit the
   * length of fields to any reasonable limit. */
  char *buf = NULL;
  size_t len = 0;

  if (upb_inttable_lookupptr(&m->name_tables, md, NULL)) {
    return;
  }

  /* TODO(haberman): handle malloc failure. */
  t = upb_gmalloc(sizeof(*t));
  upb_strtable_init(t, UPB_CTYPE_CONSTPTR);
  upb_inttable_insertptr(&m->name_tables, md, upb_value_ptr(t));

  for(upb_msg_field_begin(&i, md);
      !upb_msg_field_done(&i);
      upb_msg_field_next(&i)) {
    const upb_fielddef *f = upb_msg_iter_field(&i);

    /* Add an entry for the JSON name. */
    size_t field_len = upb_fielddef_getjsonname(f, buf, len);
    if (field_len > len) {
      size_t len2;
      buf = upb_grealloc(buf, 0, field_len);
      len = field_len;
      len2 = upb_fielddef_getjsonname(f, buf, len);
      UPB_ASSERT(len == len2);
    }
    upb_strtable_insert(t, buf, upb_value_constptr(f));

    if (strcmp(buf, upb_fielddef_name(f)) != 0) {
      /* Since the JSON name is different from the regular field name, add an
       * entry for the raw name (compliant proto3 JSON parsers must accept
       * both). */
      upb_strtable_insert(t, upb_fielddef_name(f), upb_value_constptr(f));
    }

    if (upb_fielddef_issubmsg(f)) {
      add_jsonname_table(m, upb_fielddef_msgsubdef(f));
    }
  }

  upb_gfree(buf);
}

/* Public API *****************************************************************/

upb_json_parser *upb_json_parser_create(upb_env *env,
                                        const upb_json_parsermethod *method,
                                        const upb_symtab *symbol_table,
                                        upb_sink *output) {
#ifndef NDEBUG
  const size_t size_before = upb_env_bytesallocated(env);
#endif
  upb_json_parser *p = upb_env_malloc(env, sizeof(upb_json_parser));
  if (!p) return false;

  p->env = env;
  p->method = method;
  p->limit = p->stack + UPB_JSON_MAX_DEPTH;
  p->accumulate_buf = NULL;
  p->accumulate_buf_size = 0;
  upb_bytessink_reset(&p->input_, &method->input_handler_, p);
  p->symbol_table = symbol_table;
  if (symbol_table) {
    p->any_msgdef = upb_symtab_lookupmsg(symbol_table, "google.protobuf.Any");
  } else {
    p->any_msgdef = NULL;
  }

  json_parser_reset(p);
  upb_sink_reset(&p->top->sink, output->handlers, output->closure);
  p->top->m = upb_handlers_msgdef(output->handlers);
  p->top->parse_any_round = PARSE_ANY_NOT_STARTED;
  if (p->top->m == p->any_msgdef) {
    p->top->well_known_type = WELL_KNOWN_ANY;
  } else {
    p->top->well_known_type = WELL_KNOWN_NORMAL;
  }
  set_name_table(p, p->top);

  /* If this fails, uncomment and increase the value in parser.h. */
  /* fprintf(stderr, "%zd\n", upb_env_bytesallocated(env) - size_before); */
  UPB_ASSERT_DEBUGVAR(upb_env_bytesallocated(env) - size_before <=
                      UPB_JSON_PARSER_SIZE);
  return p;
}

upb_bytessink *upb_json_parser_input(upb_json_parser *p) {
  return &p->input_;
}

upb_json_parsermethod *upb_json_parsermethod_new(const upb_msgdef* md,
                                                 const void* owner) {
  static const struct upb_refcounted_vtbl vtbl = {visit_json_parsermethod,
                                                  free_json_parsermethod};
  upb_json_parsermethod *ret = upb_gmalloc(sizeof(*ret));
  upb_refcounted_init(upb_json_parsermethod_upcast_mutable(ret), &vtbl, owner);

  ret->msg = md;
  upb_ref2(md, ret);

  upb_byteshandler_init(&ret->input_handler_);
  upb_byteshandler_setstring(&ret->input_handler_, parse, ret);
  upb_byteshandler_setendstr(&ret->input_handler_, end, ret);

  upb_inttable_init(&ret->name_tables, UPB_CTYPE_PTR);

  add_jsonname_table(ret, md);

  return ret;
}

const upb_byteshandler *upb_json_parsermethod_inputhandler(
    const upb_json_parsermethod *m) {
  return &m->input_handler_;
}
