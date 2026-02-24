using AuthServiceGO.Application.DTOs;

namespace AuthServiceGO.Application.Interfaces;

public interface IUserManagementService
{
    Task<UserResponseDto> UpdateUserRoleAsync(string userId, string roleName);
    Task<IReadOnlyList<string>> GetUserRolesAsync(string userId);
    Task<IReadOnlyList<UserResponseDto>> GetUsersByRoleAsync(string roleName);
    Task<UserResponseDto> UpdateUserDataAsync(string userId, UpdateUserDataDto dto);
    Task<UserResponseDto> ChangePasswordAsync(string userId, ChangePasswordDto dto);
}