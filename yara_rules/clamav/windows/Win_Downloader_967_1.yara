rule Win_Downloader_967_1
{
strings:
	$a0 = { b0b1a0c85bedf54573f444dbd20fb8ceea4f69665310dd8aeabdee6e364ebe4dbad20054cc2c2cd8b5046d23ca390fccc2b627727747f8e9b218199453d14d3baada134238b143a898882f3d23949452e4037d947b22a2dbf589e76c }

condition:
	$a0
}

        
