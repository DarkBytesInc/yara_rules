rule Win_Spyware_VB_550
{
strings:
	$a0 = { f541c9bd456240f09113f91b83c3569a2275f227c27203d4b9a25fca3147164da14adb87cd8f48d673aa9e16e862861dcb7343ce2b88c6218b43a63d0defea0ebf68da1d67c4b8ff212c7526aeb490e1801d35e08db4964bc5c6238b2ebc49e56c246f6c492a04875435bbe623db87f3e6ad5f10acd627bb8bd1557c8618b8d216b1854a32bb6c2b7ab76de4 }

condition:
	$a0
}

        