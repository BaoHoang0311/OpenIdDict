namespace SeverIDDictAPI.Model
{
    public class LoginModel
    {
        public string UserNameOrEmail { get;set; }
        public string Password { get;set; }
        public string ReturnUrl { get;set; }   
    }
}
