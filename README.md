# garage_clicker
dirty fast implementation of webui for garage door (rpi.gpio, tornado).

The basic garage door is operated by single button, which in this case will be connected to raspberry pi through optocoupler. So only thing which this little app does is:
* makes sure person using it is authorized to toggle the switch (tornado.auth.GoogleOAuth2Mixin)
* presses the button as per ATMOST ONCE semantics as wireless connection outside the house can be doggy at times

Some notes:
* use GPIO which state during boot won't cause your door to open for obvious reasons;)