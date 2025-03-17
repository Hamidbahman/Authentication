using SkiaSharp;
using System;

namespace Authentication.Application;

public class PuzzleCaptchaService
{
    public (byte[] BackgroundImage, byte[] PuzzlePiece, int CorrectX) GeneratePuzzleCaptcha()
    {
        int width = 300, height = 150;
        int pieceWidth = 50, pieceHeight = 50;

        using var backgroundBitmap = new SKBitmap(width, height);
        using var canvas = new SKCanvas(backgroundBitmap);
        canvas.Clear(SKColors.LightGray);

        // Draw text
        using var paint = new SKPaint { Color = SKColors.Black, IsAntialias = true, TextSize = 24 };
        canvas.DrawText("Drag the missing piece", 50, 40, paint);

        // Puzzle piece location
        int correctX = new Random().Next(50, width - 100);
        int pieceY = 75;

        // Create the puzzle piece bitmap
        using var pieceBitmap = new SKBitmap(pieceWidth, pieceHeight);
        using var pieceCanvas = new SKCanvas(pieceBitmap);
        pieceCanvas.Clear(SKColors.Transparent);

        // Copy pixels manually from the background to the puzzle piece
        for (int x = 0; x < pieceWidth; x++)
        {
            for (int y = 0; y < pieceHeight; y++)
            {
                var color = backgroundBitmap.GetPixel(correctX + x, pieceY + y);
                pieceBitmap.SetPixel(x, y, color);
            }
        }

        // Erase the original puzzle piece in the background (create an empty cutout)
        using var cutoutPaint = new SKPaint { Color = SKColors.Gray, IsAntialias = true };
        canvas.DrawRect(correctX, pieceY, pieceWidth, pieceHeight, cutoutPaint);

        // Save the modified background image
        using var bgImage = SKImage.FromBitmap(backgroundBitmap);
        using var bgData = bgImage.Encode(SKEncodedImageFormat.Png, 100);

        // Save the puzzle piece image
        using var pieceImage = SKImage.FromBitmap(pieceBitmap);
        using var pieceData = pieceImage.Encode(SKEncodedImageFormat.Png, 100);

        return (bgData.ToArray(), pieceData.ToArray(), correctX);
    }
}
