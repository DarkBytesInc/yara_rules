rule Win_Downloader_Small_2770
{
strings:
	$a0 = { 1bdf9c510bde09f1a42f2f8385e01c0eb35cdfa9d8366ec0a1575decdf35561ee9dcd42f3c8be3502a0ec0af0011023ff9cde4d4d5faf7b612f1eafde6d6bed0e16ab50c8b2548a86abd68c1fc54f44b822990d78c38c60cca310f86b816fee9811bb2c16905a95d59bcb2388d3bdb7168f8 }

condition:
	$a0
}

        
