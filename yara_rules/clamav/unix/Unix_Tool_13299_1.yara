rule Unix_Tool_13299_1
{
strings:
	$a0 = { 50730624ffffd00450730f24ffff0628e0ffbd27d7ff0f242778e0012120ef03e8ffa4afecffa0afe8ffa523ab0f02240c010101 }

condition:
	$a0
}

        
