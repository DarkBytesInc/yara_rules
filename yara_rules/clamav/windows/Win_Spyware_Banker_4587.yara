rule Win_Spyware_Banker_4587
{
strings:
	$a0 = { 5703d89266833e63cfbfada3e9eff352ae0aa5df59939ecee4d8d0154f3e32f6f92a83d095a450b567d6dd482c15572709a07a6e8de6832bb80f50d3b456b600a12757019a5d3d046b9eeb66ce1a4e12cc30d16606984c47b7be4f66c200009fb45c0c71e169dedb3da6c464b5ede88c16d45e96 }

condition:
	$a0
}

        