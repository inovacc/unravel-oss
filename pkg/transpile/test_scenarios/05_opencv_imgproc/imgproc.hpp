/*
 * imgproc.hpp - OpenCV-style image processing library
 * Inspired by opencv2/core.hpp + opencv2/imgproc.hpp
 *
 * Extreme difficulty: heavy templates, operator overloading, SIMD-like patterns,
 * Mat reference counting, ROI views, type dispatch macros
 */
#ifndef IMGPROC_HPP
#define IMGPROC_HPP

#include <iostream>
#include <vector>
#include <array>
#include <memory>
#include <cstring>
#include <cmath>
#include <cassert>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <type_traits>
#include <numeric>
#include <mutex>

namespace cv {

/* Pixel types */
enum {
    CV_8U  = 0,
    CV_8S  = 1,
    CV_16U = 2,
    CV_16S = 3,
    CV_32S = 4,
    CV_32F = 5,
    CV_64F = 6
};

#define CV_MAKETYPE(depth, cn) ((depth) | ((cn - 1) << 3))
#define CV_8UC1  CV_MAKETYPE(CV_8U, 1)
#define CV_8UC3  CV_MAKETYPE(CV_8U, 3)
#define CV_8UC4  CV_MAKETYPE(CV_8U, 4)
#define CV_32FC1 CV_MAKETYPE(CV_32F, 1)
#define CV_32FC3 CV_MAKETYPE(CV_32F, 3)
#define CV_64FC1 CV_MAKETYPE(CV_64F, 1)

inline int CV_MAT_DEPTH(int type) { return type & 7; }
inline int CV_MAT_CN(int type) { return (type >> 3) + 1; }

inline size_t elemSize1(int depth) {
    static const size_t sizes[] = {1, 1, 2, 2, 4, 4, 8};
    return sizes[depth];
}

/* Size */
struct Size {
    int width, height;
    Size() : width(0), height(0) {}
    Size(int w, int h) : width(w), height(h) {}
    int area() const { return width * height; }
    bool empty() const { return width <= 0 || height <= 0; }
    bool operator==(const Size& other) const {
        return width == other.width && height == other.height;
    }
    bool operator!=(const Size& other) const { return !(*this == other); }
};

/* Point */
template<typename T>
struct Point_ {
    T x, y;
    Point_() : x(0), y(0) {}
    Point_(T x, T y) : x(x), y(y) {}

    Point_ operator+(const Point_& p) const { return {x + p.x, y + p.y}; }
    Point_ operator-(const Point_& p) const { return {x - p.x, y - p.y}; }
    Point_ operator*(T scale) const { return {x * scale, y * scale}; }

    double norm() const { return std::sqrt(x * x + y * y); }
    T dot(const Point_& p) const { return x * p.x + y * p.y; }
};

using Point  = Point_<int>;
using Point2f = Point_<float>;
using Point2d = Point_<double>;

/* Rect */
template<typename T>
struct Rect_ {
    T x, y, width, height;
    Rect_() : x(0), y(0), width(0), height(0) {}
    Rect_(T x, T y, T w, T h) : x(x), y(y), width(w), height(h) {}

    T area() const { return width * height; }
    bool empty() const { return width <= 0 || height <= 0; }
    bool contains(const Point_<T>& p) const {
        return p.x >= x && p.x < x + width && p.y >= y && p.y < y + height;
    }

    Point_<T> tl() const { return {x, y}; }
    Point_<T> br() const { return {x + width, y + height}; }
    Size size() const { return Size(static_cast<int>(width), static_cast<int>(height)); }

    Rect_ operator&(const Rect_& r) const {
        T x1 = std::max(x, r.x);
        T y1 = std::max(y, r.y);
        T x2 = std::min(x + width, r.x + r.width);
        T y2 = std::min(y + height, r.y + r.height);
        return Rect_(x1, y1, std::max(T(0), x2 - x1), std::max(T(0), y2 - y1));
    }

    Rect_ operator|(const Rect_& r) const {
        T x1 = std::min(x, r.x);
        T y1 = std::min(y, r.y);
        T x2 = std::max(x + width, r.x + r.width);
        T y2 = std::max(y + height, r.y + r.height);
        return Rect_(x1, y1, x2 - x1, y2 - y1);
    }
};

using Rect  = Rect_<int>;
using Rect2f = Rect_<float>;

/* Scalar (like cv::Scalar — 4-element vector for pixel values) */
struct Scalar {
    double val[4];

    Scalar() { val[0] = val[1] = val[2] = val[3] = 0; }
    explicit Scalar(double v0) { val[0] = v0; val[1] = val[2] = val[3] = 0; }
    Scalar(double v0, double v1, double v2 = 0, double v3 = 0) {
        val[0] = v0; val[1] = v1; val[2] = v2; val[3] = v3;
    }

    double operator[](int i) const { return val[i]; }
    double& operator[](int i) { return val[i]; }

    static Scalar all(double v) { return Scalar(v, v, v, v); }

    Scalar operator+(const Scalar& s) const {
        return {val[0]+s.val[0], val[1]+s.val[1], val[2]+s.val[2], val[3]+s.val[3]};
    }
    Scalar operator*(double d) const {
        return {val[0]*d, val[1]*d, val[2]*d, val[3]*d};
    }
};

/* Mat — reference-counted matrix (simplified OpenCV Mat) */
class Mat {
public:
    /* Constructors */
    Mat() : rows(0), cols(0), type_(0), data_(nullptr), refcount_(nullptr),
            step_(0), datastart_(nullptr) {}

    Mat(int rows, int cols, int type)
        : rows(rows), cols(cols), type_(type) {
        create(rows, cols, type);
    }

    Mat(int rows, int cols, int type, const Scalar& s)
        : rows(rows), cols(cols), type_(type) {
        create(rows, cols, type);
        *this = s;
    }

    Mat(Size size, int type) : Mat(size.height, size.width, type) {}

    /* Copy — shares data (reference counting) */
    Mat(const Mat& m) : rows(m.rows), cols(m.cols), type_(m.type_),
                        data_(m.data_), refcount_(m.refcount_),
                        step_(m.step_), datastart_(m.datastart_) {
        if (refcount_)
            (*refcount_)++;
    }

    /* Move */
    Mat(Mat&& m) noexcept : rows(m.rows), cols(m.cols), type_(m.type_),
                            data_(m.data_), refcount_(m.refcount_),
                            step_(m.step_), datastart_(m.datastart_) {
        m.rows = m.cols = 0;
        m.data_ = nullptr;
        m.refcount_ = nullptr;
        m.datastart_ = nullptr;
    }

    ~Mat() { release(); }

    Mat& operator=(const Mat& m) {
        if (this != &m) {
            release();
            rows = m.rows;
            cols = m.cols;
            type_ = m.type_;
            data_ = m.data_;
            refcount_ = m.refcount_;
            step_ = m.step_;
            datastart_ = m.datastart_;
            if (refcount_)
                (*refcount_)++;
        }
        return *this;
    }

    Mat& operator=(Mat&& m) noexcept {
        if (this != &m) {
            release();
            rows = m.rows; cols = m.cols;
            type_ = m.type_;
            data_ = m.data_;
            refcount_ = m.refcount_;
            step_ = m.step_;
            datastart_ = m.datastart_;
            m.rows = m.cols = 0;
            m.data_ = nullptr;
            m.refcount_ = nullptr;
            m.datastart_ = nullptr;
        }
        return *this;
    }

    /* Fill with scalar */
    Mat& operator=(const Scalar& s) {
        int cn = channels();
        for (int r = 0; r < rows; r++) {
            unsigned char* row = ptr(r);
            for (int c = 0; c < cols; c++) {
                for (int k = 0; k < cn; k++) {
                    switch (depth()) {
                    case CV_8U:
                        row[c * cn + k] = static_cast<unsigned char>(s.val[k]);
                        break;
                    case CV_32F:
                        reinterpret_cast<float*>(row)[c * cn + k] = static_cast<float>(s.val[k]);
                        break;
                    case CV_64F:
                        reinterpret_cast<double*>(row)[c * cn + k] = s.val[k];
                        break;
                    default:
                        break;
                    }
                }
            }
        }
        return *this;
    }

    /* Allocate */
    void create(int rows_, int cols_, int type) {
        release();
        rows = rows_;
        cols = cols_;
        type_ = type;
        step_ = cols_ * CV_MAT_CN(type) * elemSize1(CV_MAT_DEPTH(type));
        size_t total = step_ * rows_;
        datastart_ = new unsigned char[total];
        data_ = datastart_;
        refcount_ = new int(1);
        std::memset(data_, 0, total);
    }

    void release() {
        if (refcount_) {
            (*refcount_)--;
            if (*refcount_ <= 0) {
                delete[] datastart_;
                delete refcount_;
            }
        }
        data_ = nullptr;
        datastart_ = nullptr;
        refcount_ = nullptr;
        rows = cols = 0;
    }

    /* Deep copy */
    Mat clone() const {
        Mat m(rows, cols, type_);
        size_t total = step_ * rows;
        std::memcpy(m.data_, data_, total);
        return m;
    }

    void copyTo(Mat& dst) const {
        dst = clone();
    }

    /* ROI (sub-matrix view) */
    Mat operator()(const Rect& roi) const {
        Mat m;
        m.rows = roi.height;
        m.cols = roi.width;
        m.type_ = type_;
        m.step_ = step_;
        m.data_ = data_ + roi.y * step_ + roi.x * elemSize();
        m.datastart_ = datastart_;
        m.refcount_ = refcount_;
        if (refcount_)
            (*refcount_)++;
        return m;
    }

    /* Access */
    unsigned char* ptr(int row = 0) { return data_ + row * step_; }
    const unsigned char* ptr(int row = 0) const { return data_ + row * step_; }

    template<typename T>
    T& at(int row, int col) {
        return reinterpret_cast<T*>(data_ + row * step_)[col];
    }

    template<typename T>
    const T& at(int row, int col) const {
        return reinterpret_cast<const T*>(data_ + row * step_)[col];
    }

    /* Properties */
    bool empty() const { return data_ == nullptr || rows == 0 || cols == 0; }
    Size size() const { return Size(cols, rows); }
    int type() const { return type_; }
    int depth() const { return CV_MAT_DEPTH(type_); }
    int channels() const { return CV_MAT_CN(type_); }
    size_t elemSize() const { return CV_MAT_CN(type_) * elemSize1(CV_MAT_DEPTH(type_)); }
    size_t total() const { return static_cast<size_t>(rows) * cols; }
    size_t step1() const { return step_; }

    /* Arithmetic operators */
    Mat operator+(const Mat& other) const {
        assert(rows == other.rows && cols == other.cols && type_ == other.type_);
        Mat result(rows, cols, type_);
        size_t total_bytes = step_ * rows;
        if (depth() == CV_8U) {
            for (size_t i = 0; i < total_bytes; i++) {
                int sum = static_cast<int>(data_[i]) + static_cast<int>(other.data_[i]);
                result.data_[i] = static_cast<unsigned char>(std::min(sum, 255));
            }
        }
        return result;
    }

    Mat operator-(const Mat& other) const {
        assert(rows == other.rows && cols == other.cols && type_ == other.type_);
        Mat result(rows, cols, type_);
        size_t total_bytes = step_ * rows;
        if (depth() == CV_8U) {
            for (size_t i = 0; i < total_bytes; i++) {
                int diff = static_cast<int>(data_[i]) - static_cast<int>(other.data_[i]);
                result.data_[i] = static_cast<unsigned char>(std::max(diff, 0));
            }
        }
        return result;
    }

    Mat operator*(double scale) const {
        Mat result = clone();
        size_t total_bytes = step_ * rows;
        if (depth() == CV_8U) {
            for (size_t i = 0; i < total_bytes; i++) {
                int val = static_cast<int>(std::round(data_[i] * scale));
                result.data_[i] = static_cast<unsigned char>(
                    std::max(0, std::min(val, 255)));
            }
        }
        return result;
    }

    int rows, cols;

private:
    int type_;
    unsigned char* data_;
    int* refcount_;
    size_t step_;
    unsigned char* datastart_;
};

/* Image processing functions */

/* Color conversion codes */
enum {
    COLOR_BGR2GRAY = 6,
    COLOR_BGR2RGB  = 4,
    COLOR_GRAY2BGR = 8
};

/* Threshold types */
enum {
    THRESH_BINARY     = 0,
    THRESH_BINARY_INV = 1,
    THRESH_TRUNC      = 2,
    THRESH_TOZERO     = 3,
    THRESH_TOZERO_INV = 4
};

/* Border types */
enum {
    BORDER_CONSTANT  = 0,
    BORDER_REPLICATE = 1,
    BORDER_REFLECT   = 2
};

/* Convert color space */
inline void cvtColor(const Mat& src, Mat& dst, int code) {
    if (code == COLOR_BGR2GRAY) {
        assert(src.channels() == 3);
        dst.create(src.rows, src.cols, CV_8UC1);
        for (int r = 0; r < src.rows; r++) {
            const unsigned char* srow = src.ptr(r);
            unsigned char* drow = dst.ptr(r);
            for (int c = 0; c < src.cols; c++) {
                int b = srow[c * 3 + 0];
                int g = srow[c * 3 + 1];
                int rv = srow[c * 3 + 2];
                /* Standard luminance formula */
                drow[c] = static_cast<unsigned char>(0.114 * b + 0.587 * g + 0.299 * rv);
            }
        }
    } else if (code == COLOR_GRAY2BGR) {
        assert(src.channels() == 1);
        dst.create(src.rows, src.cols, CV_8UC3);
        for (int r = 0; r < src.rows; r++) {
            const unsigned char* srow = src.ptr(r);
            unsigned char* drow = dst.ptr(r);
            for (int c = 0; c < src.cols; c++) {
                drow[c * 3 + 0] = srow[c];
                drow[c * 3 + 1] = srow[c];
                drow[c * 3 + 2] = srow[c];
            }
        }
    }
}

/* Threshold */
inline double threshold(const Mat& src, Mat& dst, double thresh,
                        double maxval, int type) {
    assert(src.channels() == 1 && src.depth() == CV_8U);
    dst.create(src.rows, src.cols, src.type());
    unsigned char t = static_cast<unsigned char>(thresh);
    unsigned char m = static_cast<unsigned char>(maxval);

    for (int r = 0; r < src.rows; r++) {
        const unsigned char* srow = src.ptr(r);
        unsigned char* drow = dst.ptr(r);
        for (int c = 0; c < src.cols; c++) {
            switch (type) {
            case THRESH_BINARY:
                drow[c] = srow[c] > t ? m : 0;
                break;
            case THRESH_BINARY_INV:
                drow[c] = srow[c] > t ? 0 : m;
                break;
            case THRESH_TRUNC:
                drow[c] = srow[c] > t ? t : srow[c];
                break;
            case THRESH_TOZERO:
                drow[c] = srow[c] > t ? srow[c] : 0;
                break;
            case THRESH_TOZERO_INV:
                drow[c] = srow[c] > t ? 0 : srow[c];
                break;
            }
        }
    }
    return thresh;
}

/* Gaussian blur (3x3 simplified) */
inline void GaussianBlur(const Mat& src, Mat& dst, Size ksize,
                         double sigmaX, double sigmaY = 0) {
    (void)sigmaX; (void)sigmaY;
    assert(src.depth() == CV_8U);
    assert(ksize.width == 3 && ksize.height == 3);

    dst.create(src.rows, src.cols, src.type());
    int cn = src.channels();

    /* 3x3 Gaussian kernel (approximation) */
    const int kernel[3][3] = {
        {1, 2, 1},
        {2, 4, 2},
        {1, 2, 1}
    };
    const int ksum = 16;

    for (int r = 1; r < src.rows - 1; r++) {
        for (int c = 1; c < src.cols - 1; c++) {
            for (int k = 0; k < cn; k++) {
                int sum = 0;
                for (int kr = -1; kr <= 1; kr++) {
                    const unsigned char* row = src.ptr(r + kr);
                    for (int kc = -1; kc <= 1; kc++) {
                        sum += row[(c + kc) * cn + k] * kernel[kr + 1][kc + 1];
                    }
                }
                dst.ptr(r)[(c * cn) + k] = static_cast<unsigned char>(sum / ksum);
            }
        }
    }
}

/* Sobel edge detection (3x3) */
inline void Sobel(const Mat& src, Mat& dst, int ddepth,
                  int dx, int dy, int ksize = 3) {
    (void)ddepth; (void)ksize;
    assert(src.channels() == 1 && src.depth() == CV_8U);

    dst.create(src.rows, src.cols, CV_8UC1);

    const int gx[3][3] = {{-1, 0, 1}, {-2, 0, 2}, {-1, 0, 1}};
    const int gy[3][3] = {{-1, -2, -1}, {0, 0, 0}, {1, 2, 1}};

    for (int r = 1; r < src.rows - 1; r++) {
        for (int c = 1; c < src.cols - 1; c++) {
            int sum = 0;
            for (int kr = -1; kr <= 1; kr++) {
                const unsigned char* row = src.ptr(r + kr);
                for (int kc = -1; kc <= 1; kc++) {
                    if (dx)
                        sum += row[c + kc] * gx[kr + 1][kc + 1];
                    if (dy)
                        sum += row[c + kc] * gy[kr + 1][kc + 1];
                }
            }
            dst.ptr(r)[c] = static_cast<unsigned char>(
                std::min(std::abs(sum), 255));
        }
    }
}

/* Resize (nearest neighbor) */
inline void resize(const Mat& src, Mat& dst, Size dsize) {
    dst.create(dsize.height, dsize.width, src.type());
    int cn = src.channels();
    double fx = static_cast<double>(src.cols) / dsize.width;
    double fy = static_cast<double>(src.rows) / dsize.height;

    for (int r = 0; r < dsize.height; r++) {
        int sr = std::min(static_cast<int>(r * fy), src.rows - 1);
        unsigned char* drow = dst.ptr(r);
        const unsigned char* srow = src.ptr(sr);
        for (int c = 0; c < dsize.width; c++) {
            int sc = std::min(static_cast<int>(c * fx), src.cols - 1);
            for (int k = 0; k < cn; k++) {
                drow[c * cn + k] = srow[sc * cn + k];
            }
        }
    }
}

/* Compute histogram for single-channel image */
inline void calcHist(const Mat& src, std::vector<int>& hist) {
    assert(src.channels() == 1 && src.depth() == CV_8U);
    hist.assign(256, 0);
    for (int r = 0; r < src.rows; r++) {
        const unsigned char* row = src.ptr(r);
        for (int c = 0; c < src.cols; c++) {
            hist[row[c]]++;
        }
    }
}

/* Mean and standard deviation */
inline Scalar mean(const Mat& src) {
    Scalar sum;
    int cn = src.channels();
    double count = static_cast<double>(src.total());

    for (int r = 0; r < src.rows; r++) {
        const unsigned char* row = src.ptr(r);
        for (int c = 0; c < src.cols; c++) {
            for (int k = 0; k < cn; k++) {
                if (src.depth() == CV_8U)
                    sum.val[k] += row[c * cn + k];
            }
        }
    }

    for (int k = 0; k < cn; k++)
        sum.val[k] /= count;

    return sum;
}

/* Draw a filled rectangle */
inline void rectangle(Mat& img, Rect rect, const Scalar& color, int thickness = 1) {
    (void)thickness;
    int cn = img.channels();
    int x1 = std::max(0, rect.x);
    int y1 = std::max(0, rect.y);
    int x2 = std::min(img.cols, rect.x + rect.width);
    int y2 = std::min(img.rows, rect.y + rect.height);

    for (int r = y1; r < y2; r++) {
        unsigned char* row = img.ptr(r);
        for (int c = x1; c < x2; c++) {
            for (int k = 0; k < std::min(cn, 4); k++) {
                row[c * cn + k] = static_cast<unsigned char>(color.val[k]);
            }
        }
    }
}

/* Simple BMP writer (uncompressed 24-bit) for testing */
inline bool imwrite(const std::string& filename, const Mat& img) {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) return false;

    Mat bgr;
    if (img.channels() == 1)
        cvtColor(img, bgr, COLOR_GRAY2BGR);
    else
        bgr = img;

    int row_stride = ((bgr.cols * 3 + 3) / 4) * 4;
    int data_size = row_stride * bgr.rows;
    int file_size = 54 + data_size;

    /* BMP header */
    unsigned char header[54] = {};
    header[0] = 'B'; header[1] = 'M';
    *(int*)&header[2] = file_size;
    *(int*)&header[10] = 54;
    *(int*)&header[14] = 40;
    *(int*)&header[18] = bgr.cols;
    *(int*)&header[22] = bgr.rows;
    *(short*)&header[26] = 1;
    *(short*)&header[28] = 24;
    *(int*)&header[34] = data_size;

    fwrite(header, 1, 54, fp);

    /* BMP stores rows bottom-to-top */
    std::vector<unsigned char> row_buf(row_stride, 0);
    for (int r = bgr.rows - 1; r >= 0; r--) {
        const unsigned char* src_row = bgr.ptr(r);
        std::memcpy(row_buf.data(), src_row, bgr.cols * 3);
        fwrite(row_buf.data(), 1, row_stride, fp);
    }

    fclose(fp);
    return true;
}

} // namespace cv

#endif /* IMGPROC_HPP */
