rule Win_Trojan_SdBot_3722
{
strings:
	$a0 = { ae9afab91351bbdf8a8456c3851f1ac93a0f93a7510c1c66a00af53f0c45ede6b20fcd66e7a3f7ee1edc654f98e0b40cd8604f6c697ce35e8f3d1b02f5fc296003b90a6f6b2c4d135cb6aac0b967bc778ba0c952d0866392cfceaa87d21e4ce3965ed1f156a81554c46327b2ee59 }

condition:
	$a0
}

        
