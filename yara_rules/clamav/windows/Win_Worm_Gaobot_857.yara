rule Win_Worm_Gaobot_857
{
strings:
	$a0 = { f567c8afc7d9337d3348ee74890998e0af93bb9de671e59456d617d25c96e707a6be2430c863d76844348c41a2f2042262a1fcade6720fb52750323144bb582d36e9e83875c74be7ea2c63c775e74ab662a10e9dfdc4d7036abe2e74c2f188ffb7ec1ee8aa67ed5949443a7c4e }

condition:
	$a0
}

        