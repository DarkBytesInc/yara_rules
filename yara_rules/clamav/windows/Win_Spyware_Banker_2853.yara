rule Win_Spyware_Banker_2853
{
strings:
	$a0 = { de33268223d0ca7329b748fad2928a6a0b719f493bd5f2b28c54554420b9e8beb49e1cb52c4c5e0ea0e040ab527ef8e4ed173ce71e87f3366b45ded9e5dddfe8fc7090f57ed26c2268cc0adcd2995702017acd6691a6479aa9da7cd8ac8cc79c74e105a5d3733312f140954c32b7a1404179906797ec55c316b58fa64792e026c514a399b92a3357b10ca6c1dc135fc3442df2cc5e70 }

condition:
	$a0
}

        