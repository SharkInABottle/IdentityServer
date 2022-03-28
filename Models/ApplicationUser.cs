// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Identity;

namespace AuthApi.Models;

// Add profile data for application users by adding properties to the ApplicationUser class
public class ApplicationUser : IdentityUser<Guid>
{
    public bool IsConfirmed { get; set; }
    public bool IsDeleted { get; set; }
    public bool IsReported { get; set; }
    public DateTime RegisteredTime { get; set; }
    public DateTime LastLogin { get; set; }
    public int ConfirmationCode { get; set; }


}
