rule Win_Worm_Mytob_3
{
strings:
	$a0 = { 7cbd6e5c92625bdcd9b4e8359039e774d8b5ca9b60342fea73d000ba0b5d6adc1823110779744bd489f09bbb1eab1ee42bef07d1bc8f52168c7bd4fffe8d217067b233ae841d0229126b5c5bfb44c41f }

condition:
	$a0
}

        
