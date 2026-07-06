/*
 * main.c - FFmpeg-style transcoder demo
 * Demonstrates the full transcoding pipeline with progress reporting
 */
#include "transcoder.h"

static void progress_callback(const TranscodeStats* stats, void* user) {
    (void)user;
    fprintf(stderr, "\rProgress: %lld frames, %lld packets, "
            "%.1f fps, %.1f MB written",
            (long long)stats->frames_processed,
            (long long)stats->packets_written,
            stats->encoding_fps,
            stats->bytes_written / (1024.0 * 1024.0));
    fflush(stderr);
}

static void custom_log(void* ctx, int level, const char* fmt, va_list args) {
    (void)ctx;
    const char* color;
    switch (level) {
    case AV_LOG_ERROR:   color = "\033[31m"; break; /* red */
    case AV_LOG_WARNING: color = "\033[33m"; break; /* yellow */
    case AV_LOG_INFO:    color = "\033[32m"; break; /* green */
    default:             color = "\033[0m";  break;
    }
    fprintf(stderr, "%s", color);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\033[0m");
}

int main(int argc, char* argv[]) {
    const char* input = "input.mp4";
    const char* output = "output.mp4";

    if (argc > 1) input = argv[1];
    if (argc > 2) output = argv[2];

    /* Set custom logger */
    av_log_set_callback(custom_log);

    printf("=== FFmpeg-style Transcoder Demo ===\n\n");

    /* Show utility functions */
    printf("Media types:\n");
    printf("  Video:    %s\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
    printf("  Audio:    %s\n", av_get_media_type_string(AVMEDIA_TYPE_AUDIO));
    printf("  Subtitle: %s\n", av_get_media_type_string(AVMEDIA_TYPE_SUBTITLE));

    printf("\nPixel formats:\n");
    printf("  YUV420P: %s\n", av_get_pix_fmt_name(AV_PIX_FMT_YUV420P));
    printf("  RGB24:   %s\n", av_get_pix_fmt_name(AV_PIX_FMT_RGB24));

    printf("\nSample formats:\n");
    printf("  S16: %s (%d bytes)\n", av_get_sample_fmt_name(AV_SAMPLE_FMT_S16),
           av_get_bytes_per_sample(AV_SAMPLE_FMT_S16));
    printf("  FLT: %s (%d bytes)\n", av_get_sample_fmt_name(AV_SAMPLE_FMT_FLT),
           av_get_bytes_per_sample(AV_SAMPLE_FMT_FLT));

    /* Test rational number functions */
    printf("\nRational arithmetic:\n");
    AVRational fps = av_make_q(30000, 1001);
    printf("  NTSC: %d/%d = %.4f fps\n", fps.num, fps.den, av_q2d(fps));

    AVRational tb_in = av_make_q(1, 90000);
    AVRational tb_out = av_make_q(1, 48000);
    int64_t pts = av_rescale_q(90000, tb_in, tb_out);
    printf("  Rescale 90000 (1/90000 -> 1/48000): %lld\n", (long long)pts);

    /* Test packet/frame lifecycle */
    printf("\n--- Packet/Frame Lifecycle ---\n");
    AVPacket* pkt = av_packet_alloc();
    printf("Packet allocated: %s\n", pkt ? "yes" : "no");

    pkt->data = (uint8_t*)malloc(256);
    pkt->size = 256;
    memset(pkt->data, 0xAB, 256);
    pkt->pts = 1000;
    pkt->dts = 900;

    AVPacket* pkt_copy = av_packet_alloc();
    av_packet_ref(pkt_copy, pkt);
    printf("Packet copy: size=%d, pts=%lld\n", pkt_copy->size, (long long)pkt_copy->pts);

    av_packet_free(&pkt);
    av_packet_free(&pkt_copy);
    printf("Packets freed: pkt=%s, copy=%s\n",
           pkt == NULL ? "null" : "leak",
           pkt_copy == NULL ? "null" : "leak");

    /* Frame test */
    AVFrame* frame = av_frame_alloc();
    frame->width = 1920;
    frame->height = 1080;
    frame->format = AV_PIX_FMT_YUV420P;
    int ret = av_frame_get_buffer(frame, 0);
    printf("\nFrame allocated: %dx%d %s (ret=%d)\n",
           frame->width, frame->height,
           av_get_pix_fmt_name((AVPixelFormat)frame->format), ret);
    printf("  Y plane: linesize=%d\n", frame->linesize[0]);
    printf("  U plane: linesize=%d\n", frame->linesize[1]);
    printf("  V plane: linesize=%d\n", frame->linesize[2]);

    AVFrame* frame_clone = av_frame_clone(frame);
    printf("Frame cloned: %s\n", frame_clone ? "yes" : "no");
    av_frame_free(&frame);
    av_frame_free(&frame_clone);

    /* Codec registry test */
    printf("\n--- Codec Registry ---\n");
    const AVCodec* h264_enc = avcodec_find_encoder(AV_CODEC_ID_H264);
    const AVCodec* h264_dec = avcodec_find_decoder(AV_CODEC_ID_H264);
    const AVCodec* aac_enc = avcodec_find_encoder(AV_CODEC_ID_AAC);
    printf("H264 encoder: %s\n", h264_enc ? h264_enc->long_name : "not found");
    printf("H264 decoder: %s\n", h264_dec ? h264_dec->long_name : "not found");
    printf("AAC encoder:  %s\n", aac_enc ? aac_enc->long_name : "not found");

    /* Codec context test */
    printf("\n--- Codec Context ---\n");
    AVCodecContext* enc_ctx = avcodec_alloc_context3(h264_enc);
    enc_ctx->width = 1280;
    enc_ctx->height = 720;
    enc_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    enc_ctx->bit_rate = 2000000;
    enc_ctx->time_base = av_make_q(1, 30);

    ret = avcodec_open2(enc_ctx, h264_enc, NULL);
    printf("Encoder opened: %s (ret=%d)\n", ret == AV_OK ? "yes" : "no", ret);
    avcodec_free_context(&enc_ctx);

    /* Run transcoder on input file (if it exists) */
    printf("\n--- Transcode ---\n");
    TranscodeConfig tc_config = {
        .video_codec   = AV_CODEC_ID_H264,
        .width         = 1280,
        .height        = 720,
        .bitrate       = 2000000,
        .fps           = 30,
        .audio_codec   = AV_CODEC_ID_AAC,
        .sample_rate   = 48000,
        .audio_bitrate = 128000,
        .channels      = 2,
        .log_level     = AV_LOG_INFO
    };

    ret = transcode(input, output, &tc_config, progress_callback, NULL);
    printf("\n\nTranscode result: %d (%s)\n", ret,
           ret == AV_OK ? "success" :
           ret == AVERROR_NOENT ? "file not found" : "error");

    printf("\nDemo complete.\n");
    return ret == AV_OK || ret == AVERROR_NOENT ? 0 : 1;
}
