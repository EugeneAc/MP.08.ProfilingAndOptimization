using System.Collections.Generic;

namespace ProfileSample.Models
{
    public class ImageModel
    {
        public string Name { get; set; }

        public byte[] Data { get; set; } 
    }

    public class NewImageModel
    {
        public string Name { get; set; }

        public string Data { get; set; }
    }
}