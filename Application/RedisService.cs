using System;
using StackExchange.Redis;

namespace Application;


public class RedisService
{
    private readonly IDatabase _redisDb;

    public RedisService(IConnectionMultiplexer connectionMultiplexer)
    {
        _redisDb = connectionMultiplexer.GetDatabase();
    }

    public async Task<string?> GetStringAsync(string key)
    {
        return await _redisDb.StringGetAsync(key);
    }

    public async Task SetStringAsync(string key, string value, TimeSpan? expiry = null)
    {
        await _redisDb.StringSetAsync(key, value, expiry);
    }
}
