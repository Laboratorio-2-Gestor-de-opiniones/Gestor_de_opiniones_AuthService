using AuthServiceGO.Application.DTOs;
using AuthServiceGO.Application.Interfaces;
using AuthServiceGO.Domain.Constants;
using AuthServiceGO.Domain.Entities;
using AuthServiceGO.Domain.Interfaces;

namespace AuthServiceGO.Application.Services;

public class UserManagementService(IUserRepository users, IRoleRepository roles, ICloudinaryService cloudinary, IPasswordHashService passwordHashService) : IUserManagementService
{
    public async Task<UserResponseDto> UpdateUserRoleAsync(string userId, string roleName)
    {
        // Normalize
        roleName = roleName?.Trim().ToUpperInvariant() ?? string.Empty;

        // Validate inputs
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("Invalid userId", nameof(userId));
        if (!RoleConstants.AllowedRoles.Contains(roleName))
            throw new InvalidOperationException($"Role not allowed. Use {RoleConstants.ADMIN_ROLE} or {RoleConstants.USER_ROLE}");

        // Load user with roles
        var user = await users.GetByIdAsync(userId);

        // If demoting an admin, prevent removing last admin
        var isUserAdmin = user.UserRoles.Any(r => r.Role.Name == RoleConstants.ADMIN_ROLE);
        if (isUserAdmin && roleName != RoleConstants.ADMIN_ROLE)
        {
            var adminCount = await roles.CountUsersInRoleAsync(RoleConstants.ADMIN_ROLE);

            if (adminCount <= 1)
            {
                throw new InvalidOperationException("Cannot remove the last administrator");
            }
        }

        // Find role entity
        var role = await roles.GetByNameAsync(roleName)
                       ?? throw new InvalidOperationException($"Role {roleName} not found");

        // Update role using repository method
        await users.UpdateUserRoleAsync(userId, role.Id);

        // Reload user with updated roles
        user = await users.GetByIdAsync(userId);

        // Map to response
        return new UserResponseDto
        {
            Id = user.Id,
            Name = user.Name,
            Surname = user.Surname,
            Username = user.Username,
            Email = user.Email,
            ProfilePicture = cloudinary.GetFullImageUrl(user.UserProfile?.ProfilePicture ?? string.Empty),
            Phone = user.UserProfile?.Phone ?? string.Empty,
            Role = role.Name,
            Status = user.Status,
            IsEmailVerified = user.UserEmail?.EmailVerified ?? false,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };
    }

    public async Task<IReadOnlyList<string>> GetUserRolesAsync(string userId)
    {
        var roleNames = await roles.GetUserRoleNamesAsync(userId);
        return roleNames;
    }

    public async Task<IReadOnlyList<UserResponseDto>> GetUsersByRoleAsync(string roleName)
    {
        roleName = roleName?.Trim().ToUpperInvariant() ?? string.Empty;
        var usersInRole = await roles.GetUsersByRoleAsync(roleName);
        return usersInRole.Select(u => new UserResponseDto
        {
            Id = u.Id,
            Name = u.Name,
            Surname = u.Surname,
            Username = u.Username,
            Email = u.Email,
            ProfilePicture = cloudinary.GetFullImageUrl(u.UserProfile?.ProfilePicture ?? string.Empty),
            Phone = u.UserProfile?.Phone ?? string.Empty,
            Role = roleName,
            Status = u.Status,
            IsEmailVerified = u.UserEmail?.EmailVerified ?? false,
            CreatedAt = u.CreatedAt,
            UpdatedAt = u.UpdatedAt
        }).ToList();
    }

    public async Task<UserResponseDto> UpdateUserDataAsync(string userId, UpdateUserDataDto dto)
    {
        // Validate inputs
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("Invalid userId", nameof(userId));

        // Load user
        var user = await users.GetByIdAsync(userId)
            ?? throw new InvalidOperationException("User not found");

        // Update user data
        if (!string.IsNullOrWhiteSpace(dto.Name))
        {
            if (dto.Name.Length > 25)
                throw new InvalidOperationException("Name cannot exceed 25 characters");
            user.Name = dto.Name.Trim();
        }

        if (!string.IsNullOrWhiteSpace(dto.Surname))
        {
            if (dto.Surname.Length > 25)
                throw new InvalidOperationException("Surname cannot exceed 25 characters");
            user.Surname = dto.Surname.Trim();
        }

        user.UpdatedAt = DateTime.UtcNow;

        // Update profile data
        if (user.UserProfile != null)
        {
            if (!string.IsNullOrWhiteSpace(dto.Phone))
            {
                if (!System.Text.RegularExpressions.Regex.IsMatch(dto.Phone, @"^\d{8}$"))
                    throw new InvalidOperationException("Phone must be exactly 8 digits");
                user.UserProfile.Phone = dto.Phone;
            }

            if (!string.IsNullOrWhiteSpace(dto.ProfilePicture))
            {
                if (dto.ProfilePicture.Length > 512)
                    throw new InvalidOperationException("Profile picture URL cannot exceed 512 characters");
                user.UserProfile.ProfilePicture = dto.ProfilePicture.Trim();
            }
        }

        // Save changes
        var updatedUser = await users.UpdateAsync(user);

        // Map to response
        var userRole = updatedUser.UserRoles.FirstOrDefault()?.Role.Name ?? "USER";
        return new UserResponseDto
        {
            Id = updatedUser.Id,
            Name = updatedUser.Name,
            Surname = updatedUser.Surname,
            Username = updatedUser.Username,
            Email = updatedUser.Email,
            ProfilePicture = cloudinary.GetFullImageUrl(updatedUser.UserProfile?.ProfilePicture ?? string.Empty),
            Phone = updatedUser.UserProfile?.Phone ?? string.Empty,
            Role = userRole,
            Status = updatedUser.Status,
            IsEmailVerified = updatedUser.UserEmail?.EmailVerified ?? false,
            CreatedAt = updatedUser.CreatedAt,
            UpdatedAt = updatedUser.UpdatedAt
        };
    }

    public async Task<UserResponseDto> ChangePasswordAsync(string userId, ChangePasswordDto dto)
    {
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("Invalid userId", nameof(userId));
        if (string.IsNullOrWhiteSpace(dto.CurrentPassword)) throw new ArgumentException("Current password is required", nameof(dto.CurrentPassword));
        if (string.IsNullOrWhiteSpace(dto.NewPassword)) throw new ArgumentException("New password is required", nameof(dto.NewPassword));
        if (string.IsNullOrWhiteSpace(dto.ConfirmPassword)) throw new ArgumentException("Confirm password is required", nameof(dto.ConfirmPassword));

        if (dto.NewPassword != dto.ConfirmPassword)
            throw new InvalidOperationException("Passwords do not match");

        if (dto.NewPassword.Length < 8)
            throw new InvalidOperationException("New password must be at least 8 characters");

        if (dto.NewPassword.Length > 255)
            throw new InvalidOperationException("New password cannot exceed 255 characters");

        var user = await users.GetByIdAsync(userId)
            ?? throw new InvalidOperationException("User not found");

        if (!passwordHashService.VerifyPassword(dto.CurrentPassword, user.Password))
            throw new InvalidOperationException("Current password is incorrect");

        if (dto.CurrentPassword == dto.NewPassword)
            throw new InvalidOperationException("New password must be different from current password");

        user.Password = passwordHashService.HashPassword(dto.NewPassword);
        user.UpdatedAt = DateTime.UtcNow;

        var updatedUser = await users.UpdateAsync(user);

        var userRole = updatedUser.UserRoles.FirstOrDefault()?.Role.Name ?? "USER";
        return new UserResponseDto
        {
            Id = updatedUser.Id,
            Name = updatedUser.Name,
            Surname = updatedUser.Surname,
            Username = updatedUser.Username,
            Email = updatedUser.Email,
            ProfilePicture = cloudinary.GetFullImageUrl(updatedUser.UserProfile?.ProfilePicture ?? string.Empty),
            Phone = updatedUser.UserProfile?.Phone ?? string.Empty,
            Role = userRole,
            Status = updatedUser.Status,
            IsEmailVerified = updatedUser.UserEmail?.EmailVerified ?? false,
            CreatedAt = updatedUser.CreatedAt,
            UpdatedAt = updatedUser.UpdatedAt
        };
    }
}
