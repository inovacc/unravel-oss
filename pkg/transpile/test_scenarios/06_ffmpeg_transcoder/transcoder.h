/*
 * transcoder.h - FFmpeg-style media transcoding framework
 * Inspired by libavformat/libavcodec/libavutil
 *
 * Pure C with: function pointers, opaque types, complex memory management,
 * error codes, codec registration, packet queues, format negotiation
 */
#ifndef TRANSCODER_H
#define TRANSCODER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

/* Error codes (FFmpeg-style negative values) */
#define AV_OK              0
#define AVERROR_EOF       -1
#define AVERROR_NOMEM     -2
#define AVERROR_INVAL     -3
#define AVERROR_NOENT     -4
#define AVERROR_NOSYS     -5
#define AVERROR_BUG       -6
#define AVERROR_AGAIN     -7
#define AVERROR_DECODER   -8
#define AVERROR_ENCODER   -9

/* Media types */
typedef enum {
    AVMEDIA_TYPE_UNKNOWN = -1,
    AVMEDIA_TYPE_VIDEO,
    AVMEDIA_TYPE_AUDIO,
    AVMEDIA_TYPE_SUBTITLE
} AVMediaType;

/* Pixel formats */
typedef enum {
    AV_PIX_FMT_NONE = -1,
    AV_PIX_FMT_YUV420P,
    AV_PIX_FMT_RGB24,
    AV_PIX_FMT_BGR24,
    AV_PIX_FMT_GRAY8,
    AV_PIX_FMT_NV12,
    AV_PIX_FMT_NV21
} AVPixelFormat;

/* Sample formats */
typedef enum {
    AV_SAMPLE_FMT_NONE = -1,
    AV_SAMPLE_FMT_U8,
    AV_SAMPLE_FMT_S16,
    AV_SAMPLE_FMT_S32,
    AV_SAMPLE_FMT_FLT,
    AV_SAMPLE_FMT_DBL
} AVSampleFormat;

/* Codec IDs */
typedef enum {
    AV_CODEC_ID_NONE = 0,
    AV_CODEC_ID_H264,
    AV_CODEC_ID_H265,
    AV_CODEC_ID_VP9,
    AV_CODEC_ID_AV1,
    AV_CODEC_ID_AAC,
    AV_CODEC_ID_MP3,
    AV_CODEC_ID_OPUS,
    AV_CODEC_ID_VORBIS,
    AV_CODEC_ID_PCM_S16LE,
    AV_CODEC_ID_SRT
} AVCodecID;

/* Rational number for timestamps */
typedef struct {
    int num;
    int den;
} AVRational;

static inline double av_q2d(AVRational r) {
    return r.den ? (double)r.num / r.den : 0.0;
}

static inline AVRational av_make_q(int num, int den) {
    AVRational r = {num, den};
    return r;
}

static inline int64_t av_rescale_q(int64_t pts, AVRational src, AVRational dst) {
    if (src.den == 0 || dst.den == 0) return 0;
    return pts * src.num * dst.den / (src.den * dst.num);
}

/* Packet — encoded data */
typedef struct AVPacket {
    uint8_t*    data;
    int         size;
    int64_t     pts;          /* presentation timestamp */
    int64_t     dts;          /* decoding timestamp */
    int64_t     duration;
    int         stream_index;
    int         flags;
    AVRational  time_base;
} AVPacket;

AVPacket* av_packet_alloc(void);
void      av_packet_free(AVPacket** pkt);
int       av_packet_ref(AVPacket* dst, const AVPacket* src);
void      av_packet_unref(AVPacket* pkt);

/* Frame — decoded data */
typedef struct AVFrame {
    uint8_t*  data[4];      /* plane pointers */
    int       linesize[4];  /* stride per plane */
    int       width, height;
    int       format;       /* AVPixelFormat or AVSampleFormat */
    int64_t   pts;
    int64_t   duration;
    AVRational time_base;

    /* Audio */
    int       nb_samples;
    int       channels;
    int       sample_rate;

    /* Internal */
    uint8_t*  buf;          /* backing buffer */
    int       buf_size;
} AVFrame;

AVFrame*  av_frame_alloc(void);
void      av_frame_free(AVFrame** frame);
int       av_frame_get_buffer(AVFrame* frame, int align);
AVFrame*  av_frame_clone(const AVFrame* src);
void      av_frame_unref(AVFrame* frame);

/* Codec context */
typedef struct AVCodecContext AVCodecContext;

/* Codec — registered encoder/decoder */
typedef struct AVCodec {
    const char*   name;
    const char*   long_name;
    AVMediaType   type;
    AVCodecID     id;

    /* Capabilities */
    int           capabilities;
    const int*    supported_samplerates;
    const AVSampleFormat* sample_fmts;
    const AVPixelFormat*  pix_fmts;

    /* Function pointers — the codec implementation */
    int (*init)(AVCodecContext* ctx);
    int (*encode)(AVCodecContext* ctx, AVPacket* pkt, const AVFrame* frame, int* got_packet);
    int (*decode)(AVCodecContext* ctx, AVFrame* frame, int* got_frame, const AVPacket* pkt);
    int (*close)(AVCodecContext* ctx);
    int (*flush)(AVCodecContext* ctx);
} AVCodec;

/* Codec context — per-stream codec state */
struct AVCodecContext {
    const AVCodec*   codec;
    AVCodecID        codec_id;
    AVMediaType      codec_type;

    /* Video */
    int              width, height;
    AVPixelFormat    pix_fmt;
    AVRational       framerate;
    AVRational       time_base;
    int              gop_size;
    int              max_b_frames;

    /* Audio */
    int              sample_rate;
    int              channels;
    AVSampleFormat   sample_fmt;
    int              frame_size;

    /* Encoding */
    int64_t          bit_rate;
    int              global_quality;
    int              flags;

    /* Internal state */
    void*            priv_data;
    int64_t          frame_number;
};

AVCodecContext* avcodec_alloc_context3(const AVCodec* codec);
void            avcodec_free_context(AVCodecContext** ctx);
int             avcodec_open2(AVCodecContext* ctx, const AVCodec* codec, void** options);
int             avcodec_send_packet(AVCodecContext* ctx, const AVPacket* pkt);
int             avcodec_receive_frame(AVCodecContext* ctx, AVFrame* frame);
int             avcodec_send_frame(AVCodecContext* ctx, const AVFrame* frame);
int             avcodec_receive_packet(AVCodecContext* ctx, AVPacket* pkt);

/* Stream */
typedef struct AVStream {
    int              index;
    AVCodecID        codec_id;
    AVMediaType      codec_type;
    AVRational       time_base;
    int64_t          duration;
    int64_t          nb_frames;

    /* Codec parameters */
    int              width, height;
    AVPixelFormat    pix_fmt;
    int              sample_rate;
    int              channels;
    AVSampleFormat   sample_fmt;
    int64_t          bit_rate;
} AVStream;

/* Format context — container (muxer/demuxer) */
typedef struct AVFormatContext {
    const char*      filename;
    int              nb_streams;
    AVStream**       streams;
    int64_t          duration;      /* in AV_TIME_BASE units */
    int64_t          bit_rate;

    /* I/O */
    FILE*            pb;
    int              flags;

    /* Internal */
    void*            priv_data;
} AVFormatContext;

AVFormatContext* avformat_alloc_context(void);
void             avformat_free_context(AVFormatContext* ctx);
int              avformat_open_input(AVFormatContext** ctx, const char* url, void* fmt, void** options);
void             avformat_close_input(AVFormatContext** ctx);
int              avformat_find_stream_info(AVFormatContext* ctx, void** options);
int              av_read_frame(AVFormatContext* ctx, AVPacket* pkt);
AVStream*        avformat_new_stream(AVFormatContext* ctx, const AVCodec* codec);

/* Codec registry */
const AVCodec* avcodec_find_encoder(AVCodecID id);
const AVCodec* avcodec_find_decoder(AVCodecID id);
void           avcodec_register(AVCodec* codec);

/* Logging */
typedef void (*av_log_callback_t)(void* ctx, int level, const char* fmt, va_list args);

#define AV_LOG_QUIET   -1
#define AV_LOG_ERROR    0
#define AV_LOG_WARNING  1
#define AV_LOG_INFO     2
#define AV_LOG_VERBOSE  3
#define AV_LOG_DEBUG    4

void av_log(void* ctx, int level, const char* fmt, ...);
void av_log_set_callback(av_log_callback_t callback);
void av_log_set_level(int level);

/* Time */
#define AV_TIME_BASE  1000000
#define AV_NOPTS_VALUE ((int64_t)0x8000000000000000LL)

/* Utility */
const char* av_get_media_type_string(AVMediaType type);
const char* av_get_pix_fmt_name(AVPixelFormat fmt);
const char* av_get_sample_fmt_name(AVSampleFormat fmt);
int         av_get_bytes_per_sample(AVSampleFormat fmt);

/* High-level transcoder */
typedef struct TranscodeConfig {
    /* Video */
    AVCodecID   video_codec;
    int         width, height;
    int         bitrate;
    int         fps;

    /* Audio */
    AVCodecID   audio_codec;
    int         sample_rate;
    int         audio_bitrate;
    int         channels;

    /* General */
    int         log_level;
} TranscodeConfig;

typedef struct TranscodeStats {
    int64_t     frames_processed;
    int64_t     packets_written;
    int64_t     bytes_written;
    double      encoding_fps;
    double      elapsed_seconds;
} TranscodeStats;

/* Progress callback */
typedef void (*transcode_progress_fn)(const TranscodeStats* stats, void* user);

int transcode(const char* input_file, const char* output_file,
              const TranscodeConfig* config,
              transcode_progress_fn progress, void* user_data);

#endif /* TRANSCODER_H */
