//go:build ignore
// +build ignore

// WARNING: This code uses OpenCV-style image processing primitives.
// The C++ source depends on a custom "imgproc.hpp" library that mimics OpenCV's cv::Mat,
// cv::Scalar, and image processing functions. A direct Go equivalent does not exist
// in the standard library. This conversion assumes the existence of a corresponding
// Go "imgproc" package that provides Mat, Scalar, Point, Rect, Size, and image
// processing functions (cvtColor, GaussianBlur, threshold, Sobel, resize, etc.).
// Manual porting or integration with a Go image processing library (e.g., gocv)
// may be required for production use.

package main

import (
	"fmt"

	"imgproc"
)

// Generate a test pattern image (gradient + shapes)
func createTestImage(width, height int) *imgproc.Mat {
	img := imgproc.NewMat(height, width, imgproc.CV_8UC3, imgproc.NewScalar(0, 0, 0))

	// Horizontal gradient
	for r := 0; r < height; r++ {
		row := img.Ptr(r)
		for c := 0; c < width; c++ {
			val := byte(c * 255 / width)
			row[c*3+0] = val       // B
			row[c*3+1] = 128       // G
			row[c*3+2] = 255 - val // R
		}
	}

	// Draw some rectangles
	imgproc.Rectangle(img, imgproc.NewRect(50, 50, 100, 80), imgproc.NewScalar(255, 0, 0))   // Blue box
	imgproc.Rectangle(img, imgproc.NewRect(200, 100, 120, 90), imgproc.NewScalar(0, 255, 0)) // Green box
	imgproc.Rectangle(img, imgproc.NewRect(100, 200, 80, 60), imgproc.NewScalar(0, 0, 255))  // Red box

	return img
}

func printMatInfo(name string, m *imgproc.Mat) {
	fmt.Printf("%s: %dx%d type=%d channels=%d depth=%d total=%d\n",
		name, m.Cols(), m.Rows(), m.Type(), m.Channels(), m.Depth(), m.Total())
}

func main() {
	fmt.Println("=== OpenCV-style Image Processing Demo ===")

	// Create test image
	img := createTestImage(640, 480)
	printMatInfo("Original", img)

	// Color conversion: BGR -> Grayscale
	fmt.Println("\n--- Color Conversion ---")
	gray := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.CvtColor(img, gray, imgproc.COLOR_BGR2GRAY)
	printMatInfo("Grayscale", gray)

	grayMean := imgproc.Mean(gray)
	fmt.Printf("Mean intensity: %f\n", grayMean[0])

	// Gaussian blur
	fmt.Println("\n--- Gaussian Blur ---")
	blurred := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.GaussianBlur(gray, blurred, imgproc.NewSize(3, 3), 1.5)
	printMatInfo("Blurred", blurred)

	// Threshold
	fmt.Println("\n--- Threshold ---")
	binary := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.Threshold(gray, binary, 128, 255, imgproc.THRESH_BINARY)
	printMatInfo("Binary", binary)

	// Count white pixels
	whiteCount := 0
	for r := 0; r < binary.Rows(); r++ {
		row := binary.Ptr(r)
		for c := 0; c < binary.Cols(); c++ {
			if row[c] == 255 {
				whiteCount++
			}
		}
	}
	fmt.Printf("White pixels: %d (%.2f%%)\n",
		whiteCount, 100.0*float64(whiteCount)/float64(binary.Total()))

	// Sobel edge detection
	fmt.Println("\n--- Sobel Edge Detection ---")
	edgesX := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	edgesY := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.Sobel(blurred, edgesX, imgproc.CV_8UC1, 1, 0)
	imgproc.Sobel(blurred, edgesY, imgproc.CV_8UC1, 0, 1)
	printMatInfo("Edges X", edgesX)
	printMatInfo("Edges Y", edgesY)

	// Combine edges
	edges := edgesX.Add(edgesY)
	printMatInfo("Combined edges", edges)

	// Resize
	fmt.Println("\n--- Resize ---")
	smallImg := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.Resize(img, smallImg, imgproc.NewSize(160, 120))
	printMatInfo("Resized", smallImg)

	upscaled := imgproc.NewMat(0, 0, 0, imgproc.NewScalar(0))
	imgproc.Resize(smallImg, upscaled, imgproc.NewSize(640, 480))
	printMatInfo("Upscaled", upscaled)

	// ROI extraction
	fmt.Println("\n--- ROI (Region of Interest) ---")
	roiRect := imgproc.NewRect(100, 100, 200, 150)
	roi := img.ROI(roiRect)
	printMatInfo("ROI", roi)

	roiMean := imgproc.Mean(roi)
	fmt.Printf("ROI mean: B=%f G=%f R=%f\n", roiMean[0], roiMean[1], roiMean[2])

	// Histogram
	fmt.Println("\n--- Histogram ---")
	hist := imgproc.CalcHist(gray)

	// Find peak
	peakVal := 0
	peakBin := 0
	for i := 0; i < 256; i++ {
		if hist[i] > peakVal {
			peakVal = hist[i]
			peakBin = i
		}
	}
	fmt.Printf("Histogram peak: bin %d (%d pixels)\n", peakBin, peakVal)

	// Reference counting test
	fmt.Println("\n--- Reference Counting ---")
	{
		a := img         // shares data
		b := img.Clone() // deep copy
		fmt.Printf("a and img share data: %s\n",
			boolToYesNo(a.Ptr(0) == img.Ptr(0)))
		fmt.Printf("b is independent: %s\n",
			boolToYesNo(b.Ptr(0) != img.Ptr(0)))
	}
	// a is destroyed, but img data survives (refcount)
	fmt.Printf("img still valid: %s\n", boolToYesNo(!img.Empty()))

	// Operator overloading
	fmt.Println("\n--- Arithmetic Operations ---")
	brightened := img.MulScalar(1.5)
	printMatInfo("Brightened", brightened)

	// Mat diff = img - small_img; // This would be size mismatch in real OpenCV
	// Skip - just show that the operator exists

	// Geometry types
	fmt.Println("\n--- Geometry Types ---")
	p1 := imgproc.NewPoint2f(1.0, 2.0)
	p2 := imgproc.NewPoint2f(3.0, 4.0)
	p3 := p1.Add(p2)
	fmt.Printf("Point addition: (%f, %f)\n", p3.X(), p3.Y())
	fmt.Printf("Distance: %f\n", p2.Sub(p1).Norm())
	fmt.Printf("Dot product: %f\n", p1.Dot(p2))

	r1 := imgproc.NewRect(10, 10, 100, 100)
	r2 := imgproc.NewRect(50, 50, 100, 100)
	intersection := r1.And(r2)
	unionRect := r1.Or(r2)
	fmt.Printf("Intersection area: %d\n", intersection.Area())
	fmt.Printf("Union area: %d\n", unionRect.Area())
	fmt.Printf("Contains (60,60): %t\n", r1.Contains(imgproc.NewPoint(60, 60)))

	// Write output
	if imgproc.Imwrite("output.bmp", img) {
		fmt.Println("\nSaved output.bmp")
	}

	fmt.Println("\nAll image processing demos complete.")
}

func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
