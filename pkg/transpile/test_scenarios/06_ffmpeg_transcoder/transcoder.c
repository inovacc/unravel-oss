/*
 * transcoder.c - FFmpeg-style media transcoding implementation
 *
 * Demonstrates: opaque types, function pointer vtables, complex memory
 * management, error propagation with goto cleanup, codec registration,
 * packet/frame lifecycle, format I/O abstraction
 */
#include "transcoder.h"

/* ========== Logging ========== */

static int g_log_level = AV_LOG_INFO;
static av_log_callback_t g_log_callback = NULL;

static void default_log(void* ctx, int level, const char* fmt, va_list args) {
    (void)ctx;
    if (level > g_log_level)
        return;
    const char* prefix;
    switch (level) {
    case AV_LOG_ERROR:   prefix = "[ERROR] "; break;
    case AV_LOG_WARNING: prefix = "[WARN]  "; break;
    case AV_LOG_INFO:    prefix = "[INFO]  "; break;
    case AV_LOG_VERBOSE: prefix = "[VERB]  "; break;
    case AV_LOG_DEBUG:   prefix = "[DEBUG] "; break;
    default:             prefix = ""; break;
    }
    fprintf(stderr, "%s", prefix);
    vfprintf(stderr, fmt, args);
}

void av_log(void* ctx, int level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (g_log_callback)
        g_log_callback(ctx, level, fmt, args);
    else
        default_log(ctx, level, fmt, args);
    va_end(args);
}

void av_log_set_callback(av_log_callback_t callback) {
    g_log_callback = callback;
}

void av_log_set_level(int level) {
    g_log_level = level;
}

/* ========== Utility ========== */

const char* av_get_media_type_string(AVMediaType type) {
    switch (type) {
    case AVMEDIA_TYPE_VIDEO:    return "video";
    case AVMEDIA_TYPE_AUDIO:    return "audio";
    case AVMEDIA_TYPE_SUBTITLE: return "subtitle";
    default:                    return "unknown";
    }
}

const char* av_get_pix_fmt_name(AVPixelFormat fmt) {
    switch (fmt) {
    case AV_PIX_FMT_YUV420P: return "yuv420p";
    case AV_PIX_FMT_RGB24:   return "rgb24";
    case AV_PIX_FMT_BGR24:   return "bgr24";
    case AV_PIX_FMT_GRAY8:   return "gray8";
    case AV_PIX_FMT_NV12:    return "nv12";
    case AV_PIX_FMT_NV21:    return "nv21";
    default:                  return "unknown";
    }
}

const char* av_get_sample_fmt_name(AVSampleFormat fmt) {
    switch (fmt) {
    case AV_SAMPLE_FMT_U8:  return "u8";
    case AV_SAMPLE_FMT_S16: return "s16";
    case AV_SAMPLE_FMT_S32: return "s32";
    case AV_SAMPLE_FMT_FLT: return "flt";
    case AV_SAMPLE_FMT_DBL: return "dbl";
    default:                 return "unknown";
    }
}

int av_get_bytes_per_sample(AVSampleFormat fmt) {
    switch (fmt) {
    case AV_SAMPLE_FMT_U8:  return 1;
    case AV_SAMPLE_FMT_S16: return 2;
    case AV_SAMPLE_FMT_S32: return 4;
    case AV_SAMPLE_FMT_FLT: return 4;
    case AV_SAMPLE_FMT_DBL: return 8;
    default:                 return 0;
    }
}

/* ========== Packet ========== */

AVPacket* av_packet_alloc(void) {
    AVPacket* pkt = (AVPacket*)calloc(1, sizeof(AVPacket));
    if (pkt) {
        pkt->pts = AV_NOPTS_VALUE;
        pkt->dts = AV_NOPTS_VALUE;
    }
    return pkt;
}

void av_packet_free(AVPacket** pkt) {
    if (!pkt || !*pkt) return;
    av_packet_unref(*pkt);
    free(*pkt);
    *pkt = NULL;
}

int av_packet_ref(AVPacket* dst, const AVPacket* src) {
    if (!dst || !src) return AVERROR_INVAL;

    *dst = *src;
    if (src->data && src->size > 0) {
        dst->data = (uint8_t*)malloc(src->size);
        if (!dst->data) return AVERROR_NOMEM;
        memcpy(dst->data, src->data, src->size);
    }
    return AV_OK;
}

void av_packet_unref(AVPacket* pkt) {
    if (!pkt) return;
    free(pkt->data);
    pkt->data = NULL;
    pkt->size = 0;
    pkt->pts = AV_NOPTS_VALUE;
    pkt->dts = AV_NOPTS_VALUE;
}

/* ========== Frame ========== */

AVFrame* av_frame_alloc(void) {
    AVFrame* frame = (AVFrame*)calloc(1, sizeof(AVFrame));
    if (frame) {
        frame->pts = AV_NOPTS_VALUE;
        frame->format = -1;
    }
    return frame;
}

void av_frame_free(AVFrame** frame) {
    if (!frame || !*frame) return;
    av_frame_unref(*frame);
    free(*frame);
    *frame = NULL;
}

int av_frame_get_buffer(AVFrame* frame, int align) {
    (void)align;
    if (!frame) return AVERROR_INVAL;

    int buf_size = 0;

    if (frame->width > 0 && frame->height > 0) {
        /* Video frame */
        AVPixelFormat fmt = (AVPixelFormat)frame->format;
        switch (fmt) {
        case AV_PIX_FMT_YUV420P:
            buf_size = frame->width * frame->height * 3 / 2;
            break;
        case AV_PIX_FMT_RGB24:
        case AV_PIX_FMT_BGR24:
            buf_size = frame->width * frame->height * 3;
            break;
        case AV_PIX_FMT_GRAY8:
            buf_size = frame->width * frame->height;
            break;
        default:
            buf_size = frame->width * frame->height * 4; /* safe default */
        }

        frame->buf = (uint8_t*)calloc(1, buf_size);
        if (!frame->buf) return AVERROR_NOMEM;
        frame->buf_size = buf_size;

        /* Set up plane pointers */
        if (fmt == AV_PIX_FMT_YUV420P) {
            frame->data[0] = frame->buf;
            frame->data[1] = frame->buf + frame->width * frame->height;
            frame->data[2] = frame->data[1] + (frame->width / 2) * (frame->height / 2);
            frame->linesize[0] = frame->width;
            frame->linesize[1] = frame->width / 2;
            frame->linesize[2] = frame->width / 2;
        } else {
            int bpp = (fmt == AV_PIX_FMT_GRAY8) ? 1 : 3;
            frame->data[0] = frame->buf;
            frame->linesize[0] = frame->width * bpp;
        }
    } else if (frame->nb_samples > 0 && frame->channels > 0) {
        /* Audio frame */
        int bps = av_get_bytes_per_sample((AVSampleFormat)frame->format);
        buf_size = frame->nb_samples * frame->channels * bps;
        frame->buf = (uint8_t*)calloc(1, buf_size);
        if (!frame->buf) return AVERROR_NOMEM;
        frame->buf_size = buf_size;
        frame->data[0] = frame->buf;
        frame->linesize[0] = buf_size;
    } else {
        return AVERROR_INVAL;
    }

    return AV_OK;
}

AVFrame* av_frame_clone(const AVFrame* src) {
    if (!src) return NULL;

    AVFrame* dst = av_frame_alloc();
    if (!dst) return NULL;

    *dst = *src;
    dst->buf = NULL;
    memset(dst->data, 0, sizeof(dst->data));

    if (src->buf && src->buf_size > 0) {
        dst->buf = (uint8_t*)malloc(src->buf_size);
        if (!dst->buf) {
            free(dst);
            return NULL;
        }
        memcpy(dst->buf, src->buf, src->buf_size);
        dst->buf_size = src->buf_size;

        /* Recalculate plane offsets */
        for (int i = 0; i < 4; i++) {
            if (src->data[i]) {
                ptrdiff_t offset = src->data[i] - src->buf;
                dst->data[i] = dst->buf + offset;
            }
        }
    }

    return dst;
}

void av_frame_unref(AVFrame* frame) {
    if (!frame) return;
    free(frame->buf);
    frame->buf = NULL;
    frame->buf_size = 0;
    memset(frame->data, 0, sizeof(frame->data));
    memset(frame->linesize, 0, sizeof(frame->linesize));
}

/* ========== Codec Registry ========== */

#define MAX_CODECS 64
static AVCodec* g_codecs[MAX_CODECS];
static int g_num_codecs = 0;

void avcodec_register(AVCodec* codec) {
    if (g_num_codecs < MAX_CODECS)
        g_codecs[g_num_codecs++] = codec;
}

const AVCodec* avcodec_find_encoder(AVCodecID id) {
    for (int i = 0; i < g_num_codecs; i++) {
        if (g_codecs[i]->id == id && g_codecs[i]->encode)
            return g_codecs[i];
    }
    return NULL;
}

const AVCodec* avcodec_find_decoder(AVCodecID id) {
    for (int i = 0; i < g_num_codecs; i++) {
        if (g_codecs[i]->id == id && g_codecs[i]->decode)
            return g_codecs[i];
    }
    return NULL;
}

/* ========== Codec Context ========== */

AVCodecContext* avcodec_alloc_context3(const AVCodec* codec) {
    AVCodecContext* ctx = (AVCodecContext*)calloc(1, sizeof(AVCodecContext));
    if (!ctx) return NULL;

    if (codec) {
        ctx->codec = codec;
        ctx->codec_id = codec->id;
        ctx->codec_type = codec->type;
    }
    ctx->pix_fmt = AV_PIX_FMT_NONE;
    ctx->sample_fmt = AV_SAMPLE_FMT_NONE;
    ctx->time_base = av_make_q(1, 25);

    return ctx;
}

void avcodec_free_context(AVCodecContext** ctx) {
    if (!ctx || !*ctx) return;
    if ((*ctx)->codec && (*ctx)->codec->close)
        (*ctx)->codec->close(*ctx);
    free((*ctx)->priv_data);
    free(*ctx);
    *ctx = NULL;
}

int avcodec_open2(AVCodecContext* ctx, const AVCodec* codec, void** options) {
    (void)options;
    if (!ctx) return AVERROR_INVAL;

    if (codec)
        ctx->codec = codec;

    if (!ctx->codec)
        return AVERROR_INVAL;

    if (ctx->codec->init) {
        int ret = ctx->codec->init(ctx);
        if (ret < 0) return ret;
    }

    av_log(NULL, AV_LOG_INFO, "Opened codec: %s\n", ctx->codec->name);
    return AV_OK;
}

int avcodec_send_packet(AVCodecContext* ctx, const AVPacket* pkt) {
    if (!ctx || !ctx->codec || !ctx->codec->decode)
        return AVERROR_INVAL;
    return AV_OK;
}

int avcodec_receive_frame(AVCodecContext* ctx, AVFrame* frame) {
    if (!ctx || !ctx->codec || !ctx->codec->decode)
        return AVERROR_INVAL;

    int got_frame = 0;
    AVPacket dummy = {0};
    int ret = ctx->codec->decode(ctx, frame, &got_frame, &dummy);
    if (ret < 0) return ret;

    if (got_frame) {
        frame->pts = ctx->frame_number++;
        return AV_OK;
    }
    return AVERROR_AGAIN;
}

int avcodec_send_frame(AVCodecContext* ctx, const AVFrame* frame) {
    if (!ctx || !ctx->codec || !ctx->codec->encode)
        return AVERROR_INVAL;
    return AV_OK;
}

int avcodec_receive_packet(AVCodecContext* ctx, AVPacket* pkt) {
    if (!ctx || !ctx->codec || !ctx->codec->encode)
        return AVERROR_INVAL;

    int got_packet = 0;
    AVFrame dummy = {0};
    int ret = ctx->codec->encode(ctx, pkt, &dummy, &got_packet);
    if (ret < 0) return ret;

    if (got_packet)
        return AV_OK;
    return AVERROR_AGAIN;
}

/* ========== Format Context ========== */

AVFormatContext* avformat_alloc_context(void) {
    return (AVFormatContext*)calloc(1, sizeof(AVFormatContext));
}

void avformat_free_context(AVFormatContext* ctx) {
    if (!ctx) return;
    for (int i = 0; i < ctx->nb_streams; i++) {
        free(ctx->streams[i]);
    }
    free(ctx->streams);
    free(ctx);
}

AVStream* avformat_new_stream(AVFormatContext* ctx, const AVCodec* codec) {
    (void)codec;
    if (!ctx) return NULL;

    AVStream** new_streams = (AVStream**)realloc(
        ctx->streams, (ctx->nb_streams + 1) * sizeof(AVStream*));
    if (!new_streams) return NULL;
    ctx->streams = new_streams;

    AVStream* st = (AVStream*)calloc(1, sizeof(AVStream));
    if (!st) return NULL;

    st->index = ctx->nb_streams;
    st->time_base = av_make_q(1, 90000);
    ctx->streams[ctx->nb_streams++] = st;

    return st;
}

int avformat_open_input(AVFormatContext** ctx, const char* url,
                        void* fmt, void** options) {
    (void)fmt; (void)options;

    if (!ctx || !url) return AVERROR_INVAL;

    if (!*ctx) {
        *ctx = avformat_alloc_context();
        if (!*ctx) return AVERROR_NOMEM;
    }

    (*ctx)->filename = url;

    FILE* fp = fopen(url, "rb");
    if (!fp) {
        av_log(NULL, AV_LOG_ERROR, "Could not open file: %s\n", url);
        return AVERROR_NOENT;
    }

    (*ctx)->pb = fp;
    av_log(NULL, AV_LOG_INFO, "Opened input: %s\n", url);

    return AV_OK;
}

void avformat_close_input(AVFormatContext** ctx) {
    if (!ctx || !*ctx) return;
    if ((*ctx)->pb) {
        fclose((*ctx)->pb);
        (*ctx)->pb = NULL;
    }
    avformat_free_context(*ctx);
    *ctx = NULL;
}

int avformat_find_stream_info(AVFormatContext* ctx, void** options) {
    (void)options;
    if (!ctx) return AVERROR_INVAL;

    /* In a real implementation, this would probe the file format */
    av_log(NULL, AV_LOG_INFO, "Found %d streams\n", ctx->nb_streams);

    for (int i = 0; i < ctx->nb_streams; i++) {
        AVStream* st = ctx->streams[i];
        av_log(NULL, AV_LOG_INFO, "  Stream #%d: %s\n",
               i, av_get_media_type_string(st->codec_type));
    }

    return AV_OK;
}

int av_read_frame(AVFormatContext* ctx, AVPacket* pkt) {
    if (!ctx || !pkt) return AVERROR_INVAL;
    if (!ctx->pb) return AVERROR_EOF;

    /* Simulate reading a packet */
    uint8_t header[8];
    size_t nread = fread(header, 1, sizeof(header), ctx->pb);
    if (nread < sizeof(header))
        return AVERROR_EOF;

    /* Create a fake packet */
    pkt->size = 1024;
    pkt->data = (uint8_t*)malloc(pkt->size);
    if (!pkt->data) return AVERROR_NOMEM;

    nread = fread(pkt->data, 1, pkt->size, ctx->pb);
    pkt->size = (int)nread;
    pkt->stream_index = 0;
    pkt->pts = ctx->duration;
    ctx->duration += 40; /* ~25fps */

    return AV_OK;
}

/* ========== Built-in Test Codecs ========== */

/* Null codec — passes through data unchanged */
static int null_codec_init(AVCodecContext* ctx) {
    av_log(ctx, AV_LOG_DEBUG, "Null codec initialized\n");
    return AV_OK;
}

static int null_codec_encode(AVCodecContext* ctx, AVPacket* pkt,
                             const AVFrame* frame, int* got_packet) {
    (void)frame;
    pkt->data = (uint8_t*)malloc(64);
    if (!pkt->data) return AVERROR_NOMEM;
    memset(pkt->data, 0, 64);
    pkt->size = 64;
    pkt->pts = ctx->frame_number;
    *got_packet = 1;
    ctx->frame_number++;
    return AV_OK;
}

static int null_codec_decode(AVCodecContext* ctx, AVFrame* frame,
                             int* got_frame, const AVPacket* pkt) {
    (void)pkt;
    frame->width = ctx->width > 0 ? ctx->width : 320;
    frame->height = ctx->height > 0 ? ctx->height : 240;
    frame->format = (int)ctx->pix_fmt;
    av_frame_get_buffer(frame, 0);
    *got_frame = 1;
    return AV_OK;
}

static int null_codec_close(AVCodecContext* ctx) {
    (void)ctx;
    return AV_OK;
}

static AVCodec null_video_encoder = {
    .name      = "null_video",
    .long_name = "Null Video Encoder",
    .type      = AVMEDIA_TYPE_VIDEO,
    .id        = AV_CODEC_ID_H264,
    .init      = null_codec_init,
    .encode    = null_codec_encode,
    .decode    = NULL,
    .close     = null_codec_close,
    .flush     = NULL,
};

static AVCodec null_video_decoder = {
    .name      = "null_video_dec",
    .long_name = "Null Video Decoder",
    .type      = AVMEDIA_TYPE_VIDEO,
    .id        = AV_CODEC_ID_H264,
    .init      = null_codec_init,
    .encode    = NULL,
    .decode    = null_codec_decode,
    .close     = null_codec_close,
    .flush     = NULL,
};

static AVCodec null_audio_encoder = {
    .name      = "null_audio",
    .long_name = "Null Audio Encoder",
    .type      = AVMEDIA_TYPE_AUDIO,
    .id        = AV_CODEC_ID_AAC,
    .init      = null_codec_init,
    .encode    = null_codec_encode,
    .decode    = NULL,
    .close     = null_codec_close,
    .flush     = NULL,
};

/* Register built-in codecs */
__attribute__((constructor))
static void register_builtin_codecs(void) {
    avcodec_register(&null_video_encoder);
    avcodec_register(&null_video_decoder);
    avcodec_register(&null_audio_encoder);
}

/* ========== High-level Transcoder ========== */

int transcode(const char* input_file, const char* output_file,
              const TranscodeConfig* config,
              transcode_progress_fn progress, void* user_data) {
    int ret = AV_OK;
    AVFormatContext* ifmt_ctx = NULL;
    AVCodecContext* dec_ctx = NULL;
    AVCodecContext* enc_ctx = NULL;
    AVPacket* pkt = NULL;
    AVFrame* frame = NULL;
    AVPacket* out_pkt = NULL;
    TranscodeStats stats = {0};
    clock_t start_time;

    if (config && config->log_level >= 0)
        av_log_set_level(config->log_level);

    av_log(NULL, AV_LOG_INFO, "Transcoding: %s -> %s\n", input_file, output_file);
    start_time = clock();

    /* Open input */
    ret = avformat_open_input(&ifmt_ctx, input_file, NULL, NULL);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "Failed to open input: %d\n", ret);
        goto cleanup;
    }

    /* Create a fake video stream for demo */
    AVStream* vstream = avformat_new_stream(ifmt_ctx, NULL);
    if (!vstream) {
        ret = AVERROR_NOMEM;
        goto cleanup;
    }
    vstream->codec_type = AVMEDIA_TYPE_VIDEO;
    vstream->codec_id = AV_CODEC_ID_H264;
    vstream->width = config ? config->width : 1920;
    vstream->height = config ? config->height : 1080;
    vstream->time_base = av_make_q(1, config ? config->fps : 25);

    ret = avformat_find_stream_info(ifmt_ctx, NULL);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "Failed to find stream info: %d\n", ret);
        goto cleanup;
    }

    /* Setup decoder */
    const AVCodec* decoder = avcodec_find_decoder(vstream->codec_id);
    if (!decoder) {
        av_log(NULL, AV_LOG_ERROR, "Decoder not found for codec %d\n", vstream->codec_id);
        ret = AVERROR_DECODER;
        goto cleanup;
    }

    dec_ctx = avcodec_alloc_context3(decoder);
    if (!dec_ctx) { ret = AVERROR_NOMEM; goto cleanup; }
    dec_ctx->width = vstream->width;
    dec_ctx->height = vstream->height;
    dec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    dec_ctx->time_base = vstream->time_base;

    ret = avcodec_open2(dec_ctx, decoder, NULL);
    if (ret < 0) { goto cleanup; }

    /* Setup encoder */
    AVCodecID enc_id = config ? config->video_codec : AV_CODEC_ID_H264;
    const AVCodec* encoder = avcodec_find_encoder(enc_id);
    if (!encoder) {
        av_log(NULL, AV_LOG_ERROR, "Encoder not found for codec %d\n", enc_id);
        ret = AVERROR_ENCODER;
        goto cleanup;
    }

    enc_ctx = avcodec_alloc_context3(encoder);
    if (!enc_ctx) { ret = AVERROR_NOMEM; goto cleanup; }
    enc_ctx->width = config ? config->width : 1920;
    enc_ctx->height = config ? config->height : 1080;
    enc_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    enc_ctx->bit_rate = config ? config->bitrate : 4000000;
    enc_ctx->time_base = av_make_q(1, config ? config->fps : 25);
    enc_ctx->gop_size = 12;
    enc_ctx->max_b_frames = 2;

    ret = avcodec_open2(enc_ctx, encoder, NULL);
    if (ret < 0) { goto cleanup; }

    /* Allocate packet and frame */
    pkt = av_packet_alloc();
    frame = av_frame_alloc();
    out_pkt = av_packet_alloc();
    if (!pkt || !frame || !out_pkt) {
        ret = AVERROR_NOMEM;
        goto cleanup;
    }

    /* Main decode-encode loop */
    av_log(NULL, AV_LOG_INFO, "Starting transcode loop...\n");
    int max_frames = 100; /* Limit for demo */

    while (stats.frames_processed < max_frames) {
        /* Read packet */
        ret = av_read_frame(ifmt_ctx, pkt);
        if (ret == AVERROR_EOF) {
            av_log(NULL, AV_LOG_INFO, "End of input reached\n");
            ret = AV_OK;
            break;
        }
        if (ret < 0) {
            av_log(NULL, AV_LOG_ERROR, "Error reading frame: %d\n", ret);
            goto cleanup;
        }

        /* Decode */
        ret = avcodec_send_packet(dec_ctx, pkt);
        if (ret < 0) {
            av_packet_unref(pkt);
            continue;
        }

        ret = avcodec_receive_frame(dec_ctx, frame);
        if (ret == AVERROR_AGAIN) {
            av_packet_unref(pkt);
            continue;
        }
        if (ret < 0) {
            av_packet_unref(pkt);
            goto cleanup;
        }

        /* Encode */
        ret = avcodec_send_frame(enc_ctx, frame);
        if (ret < 0) {
            av_frame_unref(frame);
            av_packet_unref(pkt);
            continue;
        }

        ret = avcodec_receive_packet(enc_ctx, out_pkt);
        if (ret == AV_OK) {
            stats.packets_written++;
            stats.bytes_written += out_pkt->size;
            av_packet_unref(out_pkt);
        }

        stats.frames_processed++;
        av_frame_unref(frame);
        av_packet_unref(pkt);

        /* Progress callback */
        if (progress && (stats.frames_processed % 10 == 0)) {
            clock_t now = clock();
            stats.elapsed_seconds = (double)(now - start_time) / CLOCKS_PER_SEC;
            if (stats.elapsed_seconds > 0)
                stats.encoding_fps = stats.frames_processed / stats.elapsed_seconds;
            progress(&stats, user_data);
        }
    }

    /* Final stats */
    {
        clock_t end_time = clock();
        stats.elapsed_seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        if (stats.elapsed_seconds > 0)
            stats.encoding_fps = stats.frames_processed / stats.elapsed_seconds;
    }

    av_log(NULL, AV_LOG_INFO, "Transcoding complete: %lld frames, %lld packets, "
           "%lld bytes, %.1f fps\n",
           (long long)stats.frames_processed,
           (long long)stats.packets_written,
           (long long)stats.bytes_written,
           stats.encoding_fps);

cleanup:
    av_packet_free(&pkt);
    av_packet_free(&out_pkt);
    av_frame_free(&frame);
    avcodec_free_context(&dec_ctx);
    avcodec_free_context(&enc_ctx);
    avformat_close_input(&ifmt_ctx);

    return ret;
}
