rule Win_Spyware_Banker_1333
{
strings:
	$a0 = { 0dc07571c613083254cecb6367b7e475f9cafa5871387d0eb1c74007db471985ee241e8c6217c96e42e16da5aff7d910f67dd99604dc20c78e8ce69a45adb3e6acfe2589b56565f06d296a2db1062efb746af3d8012487d4f7dee960f7d1d7f3149e8d74da00fa5958abc9e991d0cd21ff17103dd8a6722be671ebea5c480e2799bd35520a6b84f4ebace6091a8ce3144f229fb198c6 }

condition:
	$a0
}

        