rule Win_Spyware_W32_27
{
strings:
	$a0 = { 2fdb74035b9ed62f46d74cd70d72f01a17210330dbb90fc323f720dbff0327db13745db33d20120705ba23c103d0c909e1ddbdd9402767dddceb9ae6ece4dc375806da27e1030e33cba6f03ddcbe2b2fe46cb7ec374ede720355de3790354db7 }

condition:
	$a0
}

        
