rule Win_Spyware_743_2
{
strings:
	$a0 = { 164369a85f1437f1ad4b214aa00a2cb5f41f443cb5cf5aeae1f54b8e26a912de61dfcdd73a1f3890495cabd98c40c16e1d7c36cbce8e29aa4a7c2610a7048b778ea48b162c3702ad4a25683eb4d7528d8e86a2fadfd2971ac8fa }

condition:
	$a0
}

        
