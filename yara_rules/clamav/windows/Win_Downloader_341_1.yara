rule Win_Downloader_341_1
{
strings:
	$a0 = { b7127543f038ad5fdae448d14609027e263a54d524d1cd50d0cf0b7cb41edd8c8e9473572817051f4f71fce009550d69bf113a8607cb654ca8f7f5688145a0e800dd4b51030826b9ad4bc9158dd2c190c8ce646a479e254f669bb944dbd5b639935fdf3e3f113651c472541c380266294fde32cfd028b5640ad6eb23293e340612c57a9cc07e375b70d73e58914a218a3169b789 }

condition:
	$a0
}

        