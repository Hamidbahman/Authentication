using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Auhtentication.Application;
public class ImageCaptchaService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private Dictionary<string, (List<string> Images, List<string> CorrectImages)> _challenges;
    private readonly string _challengesFilePath;

    public ImageCaptchaService(IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
    {
        _httpContextAccessor = httpContextAccessor;

        _challengesFilePath = configuration["ImageCaptchaSettings:ChallengesFilePath"] ?? "challenges.json";
        LoadChallenges();
    }

    private void LoadChallenges()
    {
        if (!File.Exists(_challengesFilePath))
        {
            throw new FileNotFoundException($"Challenges file '{_challengesFilePath}' not found.");
        }

        var json = File.ReadAllText(_challengesFilePath);
        var challengeData = JsonSerializer.Deserialize<Dictionary<string, (List<string> Images, List<string> CorrectImages)>>(
            JsonDocument.Parse(json).RootElement.GetProperty("ImageChallenges").ToString());

        _challenges = challengeData ?? new Dictionary<string, (List<string> Images, List<string> CorrectImages)>();
    }

    public (string Category, List<string> Images) GenerateImageCaptcha()
    {
        if (_challenges == null || _challenges.Count == 0)
        {
            throw new Exception("No challenges available. Check the challenges.json file.");
        }

        var challengeKey = _challenges.Keys.OrderBy(_ => Guid.NewGuid()).First(); 
        var challenge = _challenges[challengeKey];

        _httpContextAccessor.HttpContext?.Session.SetString("ImageCaptcha", challengeKey);

        return (challengeKey, challenge.Images);
    }

    public bool ValidateImageCaptcha(List<string> userSelection)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null) return false;

        var challengeKey = context.Session.GetString("ImageCaptcha");
        if (challengeKey == null || !_challenges.ContainsKey(challengeKey)) return false;

        var correctImages = _challenges[challengeKey].CorrectImages;

        return userSelection.OrderBy(x => x).SequenceEqual(correctImages.OrderBy(x => x));
    }
}
