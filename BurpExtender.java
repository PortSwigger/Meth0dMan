/*
 * Meth0dMan
 * 
 * Generate custom intruder payload of all crawled directories;
 * - Useful for checking methods on all directories.
 * - Easy mode enabled: right click to send to intruder.
 * 
 * Author: Alexis Vanden Eijnde
 * Date: 10/03/2016
 * Version: 1.1.03
 */

package burp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import javax.swing.JMenuItem;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;

public class BurpExtender implements IBurpExtender, IContextMenuFactory,IIntruderPayloadGeneratorFactory {
	//global variables
	public static String MENU_NAME = "Send to Meth0dMan";
	public IBurpExtenderCallbacks mycallbacks;
	public IExtensionHelpers helpers;
	public ArrayList<byte[]> DIRECTORIES = new ArrayList<byte[]>();

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		//setup the callbacks
		this.mycallbacks = callbacks;
		this.helpers = mycallbacks.getHelpers();
		mycallbacks.setExtensionName("Meth0dMan");
		mycallbacks.registerContextMenuFactory(this);
		mycallbacks.registerIntruderPayloadGeneratorFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		//register menu item for only menus [0,2,4,6]
		if (invocation.getInvocationContext()%2 == 0 && invocation.getInvocationContext() < 8) {
			//new 'Send To Meth0dman' button
			List<JMenuItem> ret = new LinkedList<JMenuItem>();
			JMenuItem menuItem = new JMenuItem(MENU_NAME);
			menuItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent action) {
					//if clicked on button
					if (action.getActionCommand().equals(MENU_NAME)) {
						IHttpRequestResponse item[] = invocation.getSelectedMessages();
						//grab request
						IHttpRequestResponse first = item[0];
						//ternary operator return false is http, else return true
						Boolean is_secure = (first.getProtocol().toString() == "http") ? false : true;
						//set payload positions as method and root node
						List<int[]> payload_positions = getPayloadPos(first);
						//create a new intruder with selected 
						mycallbacks.sendToIntruder(first.getHost(),first.getPort(), is_secure, first.getRequest(),payload_positions);
					}
				}
			});
			ret.add(menuItem);
			return (ret);
		}
		//No new menu on other 
		return null;
	}

	public List<int[]> getPayloadPos(IHttpRequestResponse first) {
		//get all relevant positions 
		int[] method_pos = getHttpMethod(first);
		int start_dir = method_pos[1] + 1;
		int end_dir = start_dir + first.getUrl().getPath().length();
		int[] dir_pos = { start_dir, end_dir };
		//push all to final List
		List<int[]> payload_positions = new ArrayList<int[]>();
		payload_positions.add(method_pos);
		payload_positions.add(dir_pos);
		return payload_positions;
	}

	public HashSet<String> getDirs(String url) {
		//get whole URL tree (spider/discover content first!)
		IHttpRequestResponse mytree[] = mycallbacks.getSiteMap(url);
		HashSet<String> dirs = new HashSet<String>();
		for (IHttpRequestResponse req : mytree) {
			String temp = req.getUrl().getPath();
			if (temp.contains(".")) {
				//remove any files/extensions
				temp = temp.substring(0, temp.lastIndexOf('/') + 1);
			} else if (!temp.endsWith("/")) {
				//add folder extension
				temp += "/";
			}
			dirs.add(temp);
		}
		return dirs;
	}

	public int[] getHttpMethod(IHttpRequestResponse req) {
		String req_string = helpers.bytesToString(req.getRequest());
		//up to the first space - the method
		int[] method_pos = { 0, req_string.indexOf(" ") };
		return method_pos;
	}

	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
		//grab all directories as hashset
		HashSet<String> dirs = getDirs(attack.getHttpService().getProtocol()+ "://" + attack.getHttpService().getHost());
		IntruderPayloadGenerator myPayloads = new IntruderPayloadGenerator();
		DIRECTORIES.clear();
		//generate the payload list
		for (String directory : dirs) {
			DIRECTORIES.add(directory.getBytes());
		}
		return myPayloads;
	}

	@Override
	public String getGeneratorName() {
		return "Meth0dMan Payloads";
	}

	class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
		int payloadIndex;
		@Override
		public boolean hasMorePayloads() {
			return payloadIndex < DIRECTORIES.size();
		}
		//return each directory
		@Override
		public byte[] getNextPayload(byte[] baseValue) {
			byte[] payload = DIRECTORIES.get(payloadIndex);
			payloadIndex++;
			return payload;
		}
		@Override
		public void reset() {
			payloadIndex = 0;
		}
	}
}