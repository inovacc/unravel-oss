//go:build ignore
// +build ignore

package transcoder

import (
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"
)

// WARNING: This C code uses FFmpeg-style media transcoding with no direct Go equivalent.
// Manual porting is required for:
// - FFmpeg libavcodec/libavformat APIs
// - Codec registration and vtables
// - Low-level media packet/frame processing
// This conversion provides a structural equivalent but would need actual codec
// implementations or bindings to FFmpeg libraries to be functional.

// ========== Constants ==========

const (
	AVLogError   = 0
	AVLogWarning = 1
	AVLogInfo    = 2
	AVLogVerbose = 3
	AVLogDebug   = 4
)

const (
	AVOk           = 0
	AverrorInval   = -1
	AverrorNomem   = -2
	AverrorNoent   = -3
	AverrorEof     = -4
	AverrorAgain   = -5
	AverrorDecoder = -6
	AverrorEncoder = -7
)

const AVNoptsValue int64 = -1

// ========== Types ==========

type AVMediaType int

const (
	AvmediaTypeVideo AVMediaType = iota
	AvmediaTypeAudio
	AvmediaTypeSubtitle
)

type AVPixelFormat int

const (
	AVPixFmtNone AVPixelFormat = -1
	AVPixFmtYuv420p
	AVPixFmtRgb24
	AVPixFmtBgr24
	AVPixFmtGray8
	AVPixFmtNv12
	AVPixFmtNv21
)

type AVSampleFormat int

const (
	AVSampleFmtNone AVSampleFormat = -1
	AVSampleFmtU8
	AVSampleFmtS16
	AVSampleFmtS32
	AVSampleFmtFlt
	AVSampleFmtDbl
)

type AVCodecID int

const (
	AVCodecIdH264 AVCodecID = iota
	AVCodecIdAac
)

type AVRational struct {
	Num int
	Den int
}

type AVPacket struct {
	Data        []byte
	Size        int
	Pts         int64
	Dts         int64
	StreamIndex int
}

type AVFrame struct {
	Data      [4][]byte
	Linesize  [4]int
	Width     int
	Height    int
	Format    int
	Pts       int64
	NbSamples int
	Channels  int
	buf       []byte
	bufSize   int
}

type AVCodec struct {
	Name     string
	LongName string
	Type     AVMediaType
	Id       AVCodecID
	Init     func(*AVCodecContext) int
	Encode   func(*AVCodecContext, *AVPacket, *AVFrame, *int) int
	Decode   func(*AVCodecContext, *AVFrame, *int, *AVPacket) int
	Close    func(*AVCodecContext) int
	Flush    func(*AVCodecContext)
}

type AVCodecContext struct {
	Codec       *AVCodec
	CodecId     AVCodecID
	CodecType   AVMediaType
	Width       int
	Height      int
	PixFmt      AVPixelFormat
	SampleFmt   AVSampleFormat
	BitRate     int64
	TimeBase    AVRational
	GopSize     int
	MaxBFrames  int
	FrameNumber int64
	PrivData    unsafe.Pointer
}

type AVStream struct {
	Index     int
	CodecType AVMediaType
	CodecId   AVCodecID
	Width     int
	Height    int
	TimeBase  AVRational
}

type AVFormatContext struct {
	Filename  string
	Pb        *os.File
	Streams   []*AVStream
	NbStreams int
	Duration  int64
}

type TranscodeConfig struct {
	Width      int
	Height     int
	Fps        int
	Bitrate    int64
	VideoCodec AVCodecID
	LogLevel   int
}

type TranscodeStats struct {
	FramesProcessed int64
	PacketsWritten  int64
	BytesWritten    int64
	ElapsedSeconds  float64
	EncodingFps     float64
}

type TranscodeProgressFn func(*TranscodeStats, interface{})

type AVLogCallbackT func(interface{}, int, string, ...interface{})

// ========== Logging ==========

var gLogLevel = AVLogInfo
var gLogCallback AVLogCallbackT

func defaultLog(ctx interface{}, level int, format string, args ...interface{}) {
	if level > gLogLevel {
		return
	}
	var prefix string
	switch level {
	case AVLogError:
		prefix = "[ERROR] "
	case AVLogWarning:
		prefix = "[WARN]  "
	case AVLogInfo:
		prefix = "[INFO]  "
	case AVLogVerbose:
		prefix = "[VERB]  "
	case AVLogDebug:
		prefix = "[DEBUG] "
	default:
		prefix = ""
	}
	fmt.Fprint(os.Stderr, prefix)
	fmt.Fprintf(os.Stderr, format, args...)
}

func AvLog(ctx interface{}, level int, format string, args ...interface{}) {
	if gLogCallback != nil {
		gLogCallback(ctx, level, format, args...)
	} else {
		defaultLog(ctx, level, format, args...)
	}
}

func AvLogSetCallback(callback AVLogCallbackT) {
	gLogCallback = callback
}

func AvLogSetLevel(level int) {
	gLogLevel = level
}

// ========== Utility ==========

func AvGetMediaTypeString(mediaType AVMediaType) string {
	switch mediaType {
	case AvmediaTypeVideo:
		return "video"
	case AvmediaTypeAudio:
		return "audio"
	case AvmediaTypeSubtitle:
		return "subtitle"
	default:
		return "unknown"
	}
}

func AvGetPixFmtName(fmt AVPixelFormat) string {
	switch fmt {
	case AVPixFmtYuv420p:
		return "yuv420p"
	case AVPixFmtRgb24:
		return "rgb24"
	case AVPixFmtBgr24:
		return "bgr24"
	case AVPixFmtGray8:
		return "gray8"
	case AVPixFmtNv12:
		return "nv12"
	case AVPixFmtNv21:
		return "nv21"
	default:
		return "unknown"
	}
}

func AvGetSampleFmtName(fmt AVSampleFormat) string {
	switch fmt {
	case AVSampleFmtU8:
		return "u8"
	case AVSampleFmtS16:
		return "s16"
	case AVSampleFmtS32:
		return "s32"
	case AVSampleFmtFlt:
		return "flt"
	case AVSampleFmtDbl:
		return "dbl"
	default:
		return "unknown"
	}
}

func AvGetBytesPerSample(fmt AVSampleFormat) int {
	switch fmt {
	case AVSampleFmtU8:
		return 1
	case AVSampleFmtS16:
		return 2
	case AVSampleFmtS32:
		return 4
	case AVSampleFmtFlt:
		return 4
	case AVSampleFmtDbl:
		return 8
	default:
		return 0
	}
}

func AvMakeQ(num, den int) AVRational {
	return AVRational{Num: num, Den: den}
}

// ========== Packet ==========

func AvPacketAlloc() *AVPacket {
	return &AVPacket{
		Pts: AVNoptsValue,
		Dts: AVNoptsValue,
	}
}

func AvPacketFree(pkt **AVPacket) {
	if pkt == nil || *pkt == nil {
		return
	}
	AvPacketUnref(*pkt)
	*pkt = nil
}

func AvPacketRef(dst *AVPacket, src *AVPacket) int {
	if dst == nil || src == nil {
		return AverrorInval
	}

	*dst = *src
	if src.Data != nil && src.Size > 0 {
		dst.Data = make([]byte, src.Size)
		copy(dst.Data, src.Data)
	}
	return AVOk
}

func AvPacketUnref(pkt *AVPacket) {
	if pkt == nil {
		return
	}
	pkt.Data = nil
	pkt.Size = 0
	pkt.Pts = AVNoptsValue
	pkt.Dts = AVNoptsValue
}

// ========== Frame ==========

func AvFrameAlloc() *AVFrame {
	return &AVFrame{
		Pts:    AVNoptsValue,
		Format: -1,
	}
}

func AvFrameFree(frame **AVFrame) {
	if frame == nil || *frame == nil {
		return
	}
	AvFrameUnref(*frame)
	*frame = nil
}

func AvFrameGetBuffer(frame *AVFrame, align int) int {
	if frame == nil {
		return AverrorInval
	}

	var bufSize int

	if frame.Width > 0 && frame.Height > 0 {
		// Video frame
		fmt := AVPixelFormat(frame.Format)
		switch fmt {
		case AVPixFmtYuv420p:
			bufSize = frame.Width * frame.Height * 3 / 2
		case AVPixFmtRgb24, AVPixFmtBgr24:
			bufSize = frame.Width * frame.Height * 3
		case AVPixFmtGray8:
			bufSize = frame.Width * frame.Height
		default:
			bufSize = frame.Width * frame.Height * 4 // safe default
		}

		frame.buf = make([]byte, bufSize)
		frame.bufSize = bufSize

		// Set up plane pointers
		if fmt == AVPixFmtYuv420p {
			frame.Data[0] = frame.buf[0 : frame.Width*frame.Height]
			frame.Data[1] = frame.buf[frame.Width*frame.Height : frame.Width*frame.Height+(frame.Width/2)*(frame.Height/2)]
			frame.Data[2] = frame.buf[frame.Width*frame.Height+(frame.Width/2)*(frame.Height/2):]
			frame.Linesize[0] = frame.Width
			frame.Linesize[1] = frame.Width / 2
			frame.Linesize[2] = frame.Width / 2
		} else {
			bpp := 3
			if fmt == AVPixFmtGray8 {
				bpp = 1
			}
			frame.Data[0] = frame.buf
			frame.Linesize[0] = frame.Width * bpp
		}
	} else if frame.NbSamples > 0 && frame.Channels > 0 {
		// Audio frame
		bps := AvGetBytesPerSample(AVSampleFormat(frame.Format))
		bufSize = frame.NbSamples * frame.Channels * bps
		frame.buf = make([]byte, bufSize)
		frame.bufSize = bufSize
		frame.Data[0] = frame.buf
		frame.Linesize[0] = bufSize
	} else {
		return AverrorInval
	}

	return AVOk
}

func AvFrameClone(src *AVFrame) *AVFrame {
	if src == nil {
		return nil
	}

	dst := AvFrameAlloc()
	if dst == nil {
		return nil
	}

	*dst = *src
	dst.buf = nil
	dst.Data = [4][]byte{}

	if src.buf != nil && src.bufSize > 0 {
		dst.buf = make([]byte, src.bufSize)
		copy(dst.buf, src.buf)
		dst.bufSize = src.bufSize

		// Recalculate plane offsets
		for i := 0; i < 4; i++ {
			if src.Data[i] != nil {
				offset := 0
				for j := 0; j < len(src.buf); j++ {
					if len(src.Data[i]) > 0 && &src.buf[j] == &src.Data[i][0] {
						offset = j
						break
					}
				}
				if offset+len(src.Data[i]) <= len(dst.buf) {
					dst.Data[i] = dst.buf[offset : offset+len(src.Data[i])]
				}
			}
		}
	}

	return dst
}

func AvFrameUnref(frame *AVFrame) {
	if frame == nil {
		return
	}
	frame.buf = nil
	frame.bufSize = 0
	frame.Data = [4][]byte{}
	frame.Linesize = [4]int{}
}

// ========== Codec Registry ==========

const maxCodecs = 64

var gCodecs = make([]*AVCodec, 0, maxCodecs)

func AvcodecRegister(codec *AVCodec) {
	if len(gCodecs) < maxCodecs {
		gCodecs = append(gCodecs, codec)
	}
}

func AvcodecFindEncoder(id AVCodecID) *AVCodec {
	for _, codec := range gCodecs {
		if codec.Id == id && codec.Encode != nil {
			return codec
		}
	}
	return nil
}

func AvcodecFindDecoder(id AVCodecID) *AVCodec {
	for _, codec := range gCodecs {
		if codec.Id == id && codec.Decode != nil {
			return codec
		}
	}
	return nil
}

// ========== Codec Context ==========

func AvcodecAllocContext3(codec *AVCodec) *AVCodecContext {
	ctx := &AVCodecContext{
		PixFmt:    AVPixFmtNone,
		SampleFmt: AVSampleFmtNone,
		TimeBase:  AvMakeQ(1, 25),
	}

	if codec != nil {
		ctx.Codec = codec
		ctx.CodecId = codec.Id
		ctx.CodecType = codec.Type
	}

	return ctx
}

func AvcodecFreeContext(ctx **AVCodecContext) {
	if ctx == nil || *ctx == nil {
		return
	}
	if (*ctx).Codec != nil && (*ctx).Codec.Close != nil {
		(*ctx).Codec.Close(*ctx)
	}
	*ctx = nil
}

func AvcodecOpen2(ctx *AVCodecContext, codec *AVCodec, options interface{}) int {
	if ctx == nil {
		return AverrorInval
	}

	if codec != nil {
		ctx.Codec = codec
	}

	if ctx.Codec == nil {
		return AverrorInval
	}

	if ctx.Codec.Init != nil {
		ret := ctx.Codec.Init(ctx)
		if ret < 0 {
			return ret
		}
	}

	AvLog(nil, AVLogInfo, "Opened codec: %s\n", ctx.Codec.Name)
	return AVOk
}

func AvcodecSendPacket(ctx *AVCodecContext, pkt *AVPacket) int {
	if ctx == nil || ctx.Codec == nil || ctx.Codec.Decode == nil {
		return AverrorInval
	}
	return AVOk
}

func AvcodecReceiveFrame(ctx *AVCodecContext, frame *AVFrame) int {
	if ctx == nil || ctx.Codec == nil || ctx.Codec.Decode == nil {
		return AverrorInval
	}

	gotFrame := 0
	dummy := AVPacket{}
	ret := ctx.Codec.Decode(ctx, frame, &gotFrame, &dummy)
	if ret < 0 {
		return ret
	}

	if gotFrame != 0 {
		frame.Pts = ctx.FrameNumber
		ctx.FrameNumber++
		return AVOk
	}
	return AverrorAgain
}

func AvcodecSendFrame(ctx *AVCodecContext, frame *AVFrame) int {
	if ctx == nil || ctx.Codec == nil || ctx.Codec.Encode == nil {
		return AverrorInval
	}
	return AVOk
}

func AvcodecReceivePacket(ctx *AVCodecContext, pkt *AVPacket) int {
	if ctx == nil || ctx.Codec == nil || ctx.Codec.Encode == nil {
		return AverrorInval
	}

	gotPacket := 0
	dummy := AVFrame{}
	ret := ctx.Codec.Encode(ctx, pkt, &dummy, &gotPacket)
	if ret < 0 {
		return ret
	}

	if gotPacket != 0 {
		return AVOk
	}
	return AverrorAgain
}

// ========== Format Context ==========

func AvformatAllocContext() *AVFormatContext {
	return &AVFormatContext{}
}

func AvformatFreeContext(ctx *AVFormatContext) {
	if ctx == nil {
		return
	}
	ctx.Streams = nil
}

func AvformatNewStream(ctx *AVFormatContext, codec *AVCodec) *AVStream {
	if ctx == nil {
		return nil
	}

	st := &AVStream{
		Index:    ctx.NbStreams,
		TimeBase: AvMakeQ(1, 90000),
	}

	ctx.Streams = append(ctx.Streams, st)
	ctx.NbStreams++

	return st
}

func AvformatOpenInput(ctx **AVFormatContext, url string, fmt interface{}, options interface{}) int {
	if ctx == nil || url == "" {
		return AverrorInval
	}

	if *ctx == nil {
		*ctx = AvformatAllocContext()
		if *ctx == nil {
			return AverrorNomem
		}
	}

	(*ctx).Filename = url

	fp, err := os.Open(url)
	if err != nil {
		AvLog(nil, AVLogError, "Could not open file: %s\n", url)
		return AverrorNoent
	}

	(*ctx).Pb = fp
	AvLog(nil, AVLogInfo, "Opened input: %s\n", url)

	return AVOk
}

func AvformatCloseInput(ctx **AVFormatContext) {
	if ctx == nil || *ctx == nil {
		return
	}
	if (*ctx).Pb != nil {
		(*ctx).Pb.Close()
		(*ctx).Pb = nil
	}
	AvformatFreeContext(*ctx)
	*ctx = nil
}

func AvformatFindStreamInfo(ctx *AVFormatContext, options interface{}) int {
	if ctx == nil {
		return AverrorInval
	}

	AvLog(nil, AVLogInfo, "Found %d streams\n", ctx.NbStreams)

	for i := 0; i < ctx.NbStreams; i++ {
		st := ctx.Streams[i]
		AvLog(nil, AVLogInfo, "  Stream #%d: %s\n",
			i, AvGetMediaTypeString(st.CodecType))
	}

	return AVOk
}

func AvReadFrame(ctx *AVFormatContext, pkt *AVPacket) int {
	if ctx == nil || pkt == nil {
		return AverrorInval
	}
	if ctx.Pb == nil {
		return AverrorEof
	}

	// Simulate reading a packet
	header := make([]byte, 8)
	nread, err := ctx.Pb.Read(header)
	if err == io.EOF || nread < len(header) {
		return AverrorEof
	}

	// Create a fake packet
	pkt.Size = 1024
	pkt.Data = make([]byte, pkt.Size)

	nread, _ = ctx.Pb.Read(pkt.Data)
	pkt.Size = nread
	pkt.StreamIndex = 0
	pkt.Pts = ctx.Duration
	ctx.Duration += 40 // ~25fps

	return AVOk
}

// ========== Built-in Test Codecs ==========

func nullCodecInit(ctx *AVCodecContext) int {
	AvLog(ctx, AVLogDebug, "Null codec initialized\n")
	return AVOk
}

func nullCodecEncode(ctx *AVCodecContext, pkt *AVPacket, frame *AVFrame, gotPacket *int) int {
	pkt.Data = make([]byte, 64)
	pkt.Size = 64
	pkt.Pts = ctx.FrameNumber
	*gotPacket = 1
	ctx.FrameNumber++
	return AVOk
}

func nullCodecDecode(ctx *AVCodecContext, frame *AVFrame, gotFrame *int, pkt *AVPacket) int {
	if ctx.Width > 0 {
		frame.Width = ctx.Width
	} else {
		frame.Width = 320
	}
	if ctx.Height > 0 {
		frame.Height = ctx.Height
	} else {
		frame.Height = 240
	}
	frame.Format = int(ctx.PixFmt)
	AvFrameGetBuffer(frame, 0)
	*gotFrame = 1
	return AVOk
}

func nullCodecClose(ctx *AVCodecContext) int {
	return AVOk
}

var nullVideoEncoder = &AVCodec{
	Name:     "null_video",
	LongName: "Null Video Encoder",
	Type:     AvmediaTypeVideo,
	Id:       AVCodecIdH264,
	Init:     nullCodecInit,
	Encode:   nullCodecEncode,
	Decode:   nil,
	Close:    nullCodecClose,
	Flush:    nil,
}

var nullVideoDecoder = &AVCodec{
	Name:     "null_video_dec",
	LongName: "Null Video Decoder",
	Type:     AvmediaTypeVideo,
	Id:       AVCodecIdH264,
	Init:     nullCodecInit,
	Encode:   nil,
	Decode:   nullCodecDecode,
	Close:    nullCodecClose,
	Flush:    nil,
}

var nullAudioEncoder = &AVCodec{
	Name:     "null_audio",
	LongName: "Null Audio Encoder",
	Type:     AvmediaTypeAudio,
	Id:       AVCodecIdAac,
	Init:     nullCodecInit,
	Encode:   nullCodecEncode,
	Decode:   nil,
	Close:    nullCodecClose,
	Flush:    nil,
}

func init() {
	AvcodecRegister(nullVideoEncoder)
	AvcodecRegister(nullVideoDecoder)
	AvcodecRegister(nullAudioEncoder)
}

// ========== High-level Transcoder ==========

func Transcode(inputFile string, outputFile string,
	config *TranscodeConfig,
	progress TranscodeProgressFn, userData interface{}) int {

	ret := AVOk
	var ifmtCtx *AVFormatContext
	var decCtx *AVCodecContext
	var encCtx *AVCodecContext
	var pkt *AVPacket
	var frame *AVFrame
	var outPkt *AVPacket
	stats := TranscodeStats{}
	var startTime time.Time

	if config != nil && config.LogLevel >= 0 {
		AvLogSetLevel(config.LogLevel)
	}

	AvLog(nil, AVLogInfo, "Transcoding: %s -> %s\n", inputFile, outputFile)
	startTime = time.Now()

	// Open input
	ret = AvformatOpenInput(&ifmtCtx, inputFile, nil, nil)
	if ret < 0 {
		AvLog(nil, AVLogError, "Failed to open input: %d\n", ret)
		goto cleanup
	}

	// Create a fake video stream for demo
	{
		vstream := AvformatNewStream(ifmtCtx, nil)
		if vstream == nil {
			ret = AverrorNomem
			goto cleanup
		}
		vstream.CodecType = AvmediaTypeVideo
		vstream.CodecId = AVCodecIdH264
		if config != nil {
			vstream.Width = config.Width
			vstream.Height = config.Height
			vstream.TimeBase = AvMakeQ(1, config.Fps)
		} else {
			vstream.Width = 1920
			vstream.Height = 1080
			vstream.TimeBase = AvMakeQ(1, 25)
		}
	}

	ret = AvformatFindStreamInfo(ifmtCtx, nil)
	if ret < 0 {
		AvLog(nil, AVLogError, "Failed to find stream info: %d\n", ret)
		goto cleanup
	}

	// Setup decoder
	{
		vstream := ifmtCtx.Streams[0]
		decoder := AvcodecFindDecoder(vstream.CodecId)
		if decoder == nil {
			AvLog(nil, AVLogError, "Decoder not found for codec %d\n", vstream.CodecId)
			ret = AverrorDecoder
			goto cleanup
		}

		decCtx = AvcodecAllocContext3(decoder)
		if decCtx == nil {
			ret = AverrorNomem
			goto cleanup
		}
		decCtx.Width = vstream.Width
		decCtx.Height = vstream.Height
		decCtx.PixFmt = AVPixFmtYuv420p
		decCtx.TimeBase = vstream.TimeBase

		ret = AvcodecOpen2(decCtx, decoder, nil)
		if ret < 0 {
			goto cleanup
		}
	}

	// Setup encoder
	{
		var encId AVCodecID
		if config != nil {
			encId = config.VideoCodec
		} else {
			encId = AVCodecIdH264
		}
		encoder := AvcodecFindEncoder(encId)
		if encoder == nil {
			AvLog(nil, AVLogError, "Encoder not found for codec %d\n", encId)
			ret = AverrorEncoder
			goto cleanup
		}

		encCtx = AvcodecAllocContext3(encoder)
		if encCtx == nil {
			ret = AverrorNomem
			goto cleanup
		}
		if config != nil {
			encCtx.Width = config.Width
			encCtx.Height = config.Height
			encCtx.BitRate = config.Bitrate
			encCtx.TimeBase = AvMakeQ(1, config.Fps)
		} else {
			encCtx.Width = 1920
			encCtx.Height = 1080
			encCtx.BitRate = 4000000
			encCtx.TimeBase = AvMakeQ(1, 25)
		}
		encCtx.PixFmt = AVPixFmtYuv420p
		encCtx.GopSize = 12
		encCtx.MaxBFrames = 2

		ret = AvcodecOpen2(encCtx, encoder, nil)
		if ret < 0 {
			goto cleanup
		}
	}

	// Allocate packet and frame
	pkt = AvPacketAlloc()
	frame = AvFrameAlloc()
	outPkt = AvPacketAlloc()
	if pkt == nil || frame == nil || outPkt == nil {
		ret = AverrorNomem
		goto cleanup
	}

	// Main decode-encode loop
	AvLog(nil, AVLogInfo, "Starting transcode loop...\n")
	{
		maxFrames := int64(100) // Limit for demo

		for stats.FramesProcessed < maxFrames {
			// Read packet
			ret = AvReadFrame(ifmtCtx, pkt)
			if ret == AverrorEof {
				AvLog(nil, AVLogInfo, "End of input reached\n")
				ret = AVOk
				break
			}
			if ret < 0 {
				AvLog(nil, AVLogError, "Error reading frame: %d\n", ret)
				goto cleanup
			}

			// Decode
			ret = AvcodecSendPacket(decCtx, pkt)
			if ret < 0 {
				AvPacketUnref(pkt)
				continue
			}

			ret = AvcodecReceiveFrame(decCtx, frame)
			if ret == AverrorAgain {
				AvPacketUnref(pkt)
				continue
			}
			if ret < 0 {
				AvPacketUnref(pkt)
				goto cleanup
			}

			// Encode
			ret = AvcodecSendFrame(encCtx, frame)
			if ret < 0 {
				AvFrameUnref(frame)
				AvPacketUnref(pkt)
				continue
			}

			ret = AvcodecReceivePacket(encCtx, outPkt)
			if ret == AVOk {
				stats.PacketsWritten++
				stats.BytesWritten += int64(outPkt.Size)
				AvPacketUnref(outPkt)
			}

			stats.FramesProcessed++
			AvFrameUnref(frame)
			AvPacketUnref(pkt)

			// Progress callback
			if progress != nil && (stats.FramesProcessed%10 == 0) {
				now := time.Now()
				stats.ElapsedSeconds = now.Sub(startTime).Seconds()
				if stats.ElapsedSeconds > 0 {
					stats.EncodingFps = float64(stats.FramesProcessed) / stats.ElapsedSeconds
				}
				progress(&stats, userData)
			}
		}
	}

	// Final stats
	{
		endTime := time.Now()
		stats.ElapsedSeconds = endTime.Sub(startTime).Seconds()
		if stats.ElapsedSeconds > 0 {
			stats.EncodingFps = float64(stats.FramesProcessed) / stats.ElapsedSeconds
		}
	}

	AvLog(nil, AVLogInfo, "Transcoding complete: %d frames, %d packets, "+
		"%d bytes, %.1f fps\n",
		stats.FramesProcessed,
		stats.PacketsWritten,
		stats.BytesWritten,
		stats.EncodingFps)

cleanup:
	AvPacketFree(&pkt)
	AvPacketFree(&outPkt)
	AvFrameFree(&frame)
	AvcodecFreeContext(&decCtx)
	AvcodecFreeContext(&encCtx)
	AvformatCloseInput(&ifmtCtx)

	return ret
}
