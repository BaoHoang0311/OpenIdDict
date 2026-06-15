using Microsoft.AspNetCore.Mvc;

namespace ResourceAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GoogleAPIControlller : ControllerBase
    {
        public GoogleAPIControlller()
        {

        }
        [HttpGet]
        public async Task<IActionResult> DriveUploadBasic()
        {
            var res = Testt();
            // Follow
            // 1.Gọi API Postman google,
            // 2.Xong returnURl lấy code (dùng code lấy thông accesstoken+refreshtoken)
            // 3.Dùng accesstoken lấy thông tin của User
            // 4.Tra thông tin User, (ví dụ lấy name + gmail) để tra (trong project Sav user lúc register dùng email + name này để login)

            // Note: Đăng nhập = google lưu database (UserName + Email) giống nhau

            return Ok("Google API is working");
        }
        private string Testt()
        {
            //https://oauth2.googleapis.com/token?client_id=421450881937-np3le56aadumlvrno87aedvg43spmvi0.apps.googleusercontent.com
            //&refresh_token=ttt
            //&grant_type=refresh_token
            //&client_secret=ttt


            // Sign In Google 
            // Tạo link trong trả url về
            return null;
        }
        private string DriveUploadBasic(string filePath)
        {
            // Dùng PostMan gọi hết, ko có hàm xây sẵn như bên nodejs đâu
            return null;
        }
    }
}
