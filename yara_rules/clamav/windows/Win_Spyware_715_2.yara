rule Win_Spyware_715_2
{
strings:
	$a0 = { 7ddf38967c885e8bb8467a99578be31dd8c884d41e06f70a84b23c5a07d613b7f9c12810b8eda97de5676d0aa2e40acab5c46624c39bd145ed3b082b2da7d1d4eb2b7dcc534634c5b0a83c5aed379c03feddd516e761ebec855f7da1369e12e228f2cf9a }

condition:
	$a0
}

        
