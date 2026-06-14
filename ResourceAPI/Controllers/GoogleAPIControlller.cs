using Azure.Core;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Drive.v3;
using Google.Apis.Services;
using Google.Apis.Util.Store;
using Microsoft.AspNetCore.Mvc;

namespace ResourceAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GoogleAPIControlller : ControllerBase
    {
        private static readonly string[] Scopes = new[] { DriveService.Scope.DriveFile, DriveService.Scope.Drive };

        public GoogleAPIControlller()
        {

        }
        [HttpGet]
        public async Task<IActionResult> DriveUploadBasic()
        {
            var res = Testt();
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
