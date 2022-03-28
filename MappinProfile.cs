using AuthApi.Models;
using AutoMapper;


namespace AuthApi
{
    public class MappinProfile : Profile
    {
        public MappinProfile()
        {
            CreateMap<RegisterModel, ApplicationUser>();
        }
    }
}
