# Processor to update Jamf Title Editor
  This was originally written by LazyMacAdmin. I've made some changes for security and to fit into my environment better.
[UpdateTitleEditor](https://github.com/lazymacadmin/UpdateTitleEditor#updatetitleeditorpy)  

## UpdateTitleEditor.py
Autopkg processor to update Jamf's Title Editor

To use, you will need to run setup_keychain_credentials.py to setup the credentials on your Mac's keychain. It will also move your creds into keychain and delete the keys from preferences if you are already using the original method for your Title Editor credentials.

- As written you will also need to know the ***numeric*** ID of each title from Title Editor and use it as an input in each recipe as shown circled in red.<br/> ![Image of the Title Editor URL](Images/TitleEditorId.png)
- Make sure not to use a trailing slash on your Title Editor URL as shown:<br/> ![Title Editor Url](Images/TitleEditorUrl.png)

- There is a debug option to ensure you are getting the responses you expect. Run your recipe with `--key debug=true`
