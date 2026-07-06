/*
 * main.cpp - OpenCV-style image processing pipeline demo
 * Creates a test image and applies various transformations
 */
#include "imgproc.hpp"

using namespace cv;

/* Generate a test pattern image (gradient + shapes) */
Mat create_test_image(int width, int height) {
    Mat img(height, width, CV_8UC3, Scalar(0, 0, 0));

    /* Horizontal gradient */
    for (int r = 0; r < height; r++) {
        unsigned char* row = img.ptr(r);
        for (int c = 0; c < width; c++) {
            unsigned char val = static_cast<unsigned char>(c * 255 / width);
            row[c * 3 + 0] = val;            // B
            row[c * 3 + 1] = 128;            // G
            row[c * 3 + 2] = 255 - val;      // R
        }
    }

    /* Draw some rectangles */
    rectangle(img, Rect(50, 50, 100, 80), Scalar(255, 0, 0));     // Blue box
    rectangle(img, Rect(200, 100, 120, 90), Scalar(0, 255, 0));   // Green box
    rectangle(img, Rect(100, 200, 80, 60), Scalar(0, 0, 255));    // Red box

    return img;
}

void print_mat_info(const std::string& name, const Mat& m) {
    std::cout << name << ": " << m.cols << "x" << m.rows
              << " type=" << m.type()
              << " channels=" << m.channels()
              << " depth=" << m.depth()
              << " total=" << m.total()
              << std::endl;
}

int main() {
    std::cout << "=== OpenCV-style Image Processing Demo ===" << std::endl;

    /* Create test image */
    Mat img = create_test_image(640, 480);
    print_mat_info("Original", img);

    /* Color conversion: BGR -> Grayscale */
    std::cout << "\n--- Color Conversion ---" << std::endl;
    Mat gray;
    cvtColor(img, gray, COLOR_BGR2GRAY);
    print_mat_info("Grayscale", gray);

    Scalar gray_mean = mean(gray);
    std::cout << "Mean intensity: " << gray_mean[0] << std::endl;

    /* Gaussian blur */
    std::cout << "\n--- Gaussian Blur ---" << std::endl;
    Mat blurred;
    GaussianBlur(gray, blurred, Size(3, 3), 1.5);
    print_mat_info("Blurred", blurred);

    /* Threshold */
    std::cout << "\n--- Threshold ---" << std::endl;
    Mat binary;
    threshold(gray, binary, 128, 255, THRESH_BINARY);
    print_mat_info("Binary", binary);

    /* Count white pixels */
    int white_count = 0;
    for (int r = 0; r < binary.rows; r++) {
        const unsigned char* row = binary.ptr(r);
        for (int c = 0; c < binary.cols; c++) {
            if (row[c] == 255) white_count++;
        }
    }
    std::cout << "White pixels: " << white_count
              << " (" << (100.0 * white_count / binary.total()) << "%)"
              << std::endl;

    /* Sobel edge detection */
    std::cout << "\n--- Sobel Edge Detection ---" << std::endl;
    Mat edges_x, edges_y;
    Sobel(blurred, edges_x, CV_8UC1, 1, 0);
    Sobel(blurred, edges_y, CV_8UC1, 0, 1);
    print_mat_info("Edges X", edges_x);
    print_mat_info("Edges Y", edges_y);

    /* Combine edges */
    Mat edges = edges_x + edges_y;
    print_mat_info("Combined edges", edges);

    /* Resize */
    std::cout << "\n--- Resize ---" << std::endl;
    Mat small_img;
    resize(img, small_img, Size(160, 120));
    print_mat_info("Resized", small_img);

    Mat upscaled;
    resize(small_img, upscaled, Size(640, 480));
    print_mat_info("Upscaled", upscaled);

    /* ROI extraction */
    std::cout << "\n--- ROI (Region of Interest) ---" << std::endl;
    Rect roi_rect(100, 100, 200, 150);
    Mat roi = img(roi_rect);
    print_mat_info("ROI", roi);

    Scalar roi_mean = mean(roi);
    std::cout << "ROI mean: B=" << roi_mean[0]
              << " G=" << roi_mean[1]
              << " R=" << roi_mean[2] << std::endl;

    /* Histogram */
    std::cout << "\n--- Histogram ---" << std::endl;
    std::vector<int> hist;
    calcHist(gray, hist);

    /* Find peak */
    int peak_val = 0, peak_bin = 0;
    for (int i = 0; i < 256; i++) {
        if (hist[i] > peak_val) {
            peak_val = hist[i];
            peak_bin = i;
        }
    }
    std::cout << "Histogram peak: bin " << peak_bin
              << " (" << peak_val << " pixels)" << std::endl;

    /* Reference counting test */
    std::cout << "\n--- Reference Counting ---" << std::endl;
    {
        Mat a = img;          // shares data
        Mat b = img.clone();  // deep copy
        std::cout << "a and img share data: "
                  << (a.ptr() == img.ptr() ? "yes" : "no") << std::endl;
        std::cout << "b is independent: "
                  << (b.ptr() != img.ptr() ? "yes" : "no") << std::endl;
    }
    /* a is destroyed, but img data survives (refcount) */
    std::cout << "img still valid: " << (!img.empty() ? "yes" : "no") << std::endl;

    /* Operator overloading */
    std::cout << "\n--- Arithmetic Operations ---" << std::endl;
    Mat brightened = img * 1.5;
    print_mat_info("Brightened", brightened);

    Mat diff = img - small_img; // This would be size mismatch in real OpenCV
    // Skip - just show that the operator exists

    /* Geometry types */
    std::cout << "\n--- Geometry Types ---" << std::endl;
    Point2f p1(1.0f, 2.0f), p2(3.0f, 4.0f);
    Point2f p3 = p1 + p2;
    std::cout << "Point addition: (" << p3.x << ", " << p3.y << ")" << std::endl;
    std::cout << "Distance: " << (p2 - p1).norm() << std::endl;
    std::cout << "Dot product: " << p1.dot(p2) << std::endl;

    Rect r1(10, 10, 100, 100);
    Rect r2(50, 50, 100, 100);
    Rect intersection = r1 & r2;
    Rect union_rect = r1 | r2;
    std::cout << "Intersection area: " << intersection.area() << std::endl;
    std::cout << "Union area: " << union_rect.area() << std::endl;
    std::cout << "Contains (60,60): " << r1.contains(Point(60, 60)) << std::endl;

    /* Write output */
    if (imwrite("output.bmp", img))
        std::cout << "\nSaved output.bmp" << std::endl;

    std::cout << "\nAll image processing demos complete." << std::endl;
    return 0;
}
