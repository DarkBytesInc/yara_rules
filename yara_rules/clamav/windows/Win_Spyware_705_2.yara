rule Win_Spyware_705_2
{
strings:
	$a0 = { 844ac4f08895c4efc3600a63a7cd7f82ae1f1cf079069cb2e64e865efd21b759f1b531af5fd81efcc7292efddb31722c265f96b28eb1d334a040e2a43e77dd1c39a085f45b76f45c497555d0aca8cc03db75ab50662f662ffcd746f175ba9d2eb1f31c2a }

condition:
	$a0
}

        
