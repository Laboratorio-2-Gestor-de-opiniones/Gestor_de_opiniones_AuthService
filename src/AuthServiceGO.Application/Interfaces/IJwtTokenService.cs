
using AuthServiceGO.Domain.Entities;

namespace AuthServiceGO.Application.Interfaces;

public interface IJwtTokenService
{
    string GenerateToken(User user);
}