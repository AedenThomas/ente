import { useState, useEffect } from "react";
import { 
  List, 
  Action, 
  ActionPanel, 
  Icon, 
  Color, 
  showToast, 
  Toast,
  useNavigation,
  Clipboard
} from "@raycast/api";
import { getAuthenticatorService } from "./services/authenticator";
import { getStorageService } from "./services/storage";
import { AuthCode } from "./types";
import Login from "./login";

export default function Index() {
  const { push } = useNavigation();
  const [codes, setCodes] = useState<AuthCode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchText, setSearchText] = useState("");
  const [timer, setTimer] = useState<NodeJS.Timeout | null>(null);
  
  // Filter codes based on search
  const filteredCodes = codes.filter(
    (code) =>
      code.name.toLowerCase().includes(searchText.toLowerCase()) ||
      (code.issuer && code.issuer.toLowerCase().includes(searchText.toLowerCase()))
  );
  
  // Load and refresh codes
  const loadCodes = async () => {
    try {
      const authenticatorService = getAuthenticatorService();
      const initialized = await authenticatorService.init();
      
      if (!initialized) {
        // Not logged in or initialized, redirect to login
        push(<Login />);
        return;
      }
      
      // Authenticator successfully initialized
      await showToast({
        style: Toast.Style.Success,
        title: "Authenticator initialized",
      });
      
      // Get current codes
      try {
        const authCodes = await authenticatorService.getAuthCodes();
        
        if (!authCodes || authCodes.length === 0) {
          await showToast({
            style: Toast.Style.Warning,
            title: "No authentication codes found",
            message: "Try syncing with the server or adding codes in the Ente app"
          });
        }
        
        setCodes(authCodes);
      } catch (error) {
        console.error("Error getting auth codes:", error);
        await showToast({
          style: Toast.Style.Failure,
          title: "Failed to get authentication codes",
          message: "Please try syncing with the server"
        });
        setCodes([]);
      }
    } catch (error) {
      console.error("Error loading codes:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Failed to load authentication codes",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Sync with server
  const syncCodes = async () => {
    try {
      setIsLoading(true);
      
      const toast = await showToast({
        style: Toast.Style.Animated,
        title: "Syncing authenticator codes...",
      });
      
      const authenticatorService = getAuthenticatorService();
      // Sync with server
      const syncResult = await authenticatorService.syncAuthenticator();
      
      if (!syncResult) {
        throw new Error("Sync failed");
      }
      
      // Refresh codes after sync
      const authCodes = await authenticatorService.getAuthCodes();
      
      if (!authCodes || authCodes.length === 0) {
        await showToast({
          style: Toast.Style.Warning,
          title: "No authentication codes found after sync",
          message: "Try adding codes in the Ente app first"
        });
      }
      
      setCodes(authCodes);
      
      toast.style = Toast.Style.Success;
      toast.title = "Synced successfully!";
    } catch (error) {
      console.error("Sync error:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Sync failed",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Logout action
  const handleLogout = async () => {
    try {
      const toast = await showToast({
        style: Toast.Style.Animated,
        title: "Logging out...",
      });
      
      const storage = getStorageService();
      await storage.clearAll();
      
      toast.style = Toast.Style.Success;
      toast.title = "Logged out successfully!";
      
      // Redirect to login
      push(Login);
    } catch (error) {
      console.error("Logout error:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Logout failed",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };
  
  // Copy code to clipboard
  const copyCode = async (code: string) => {
    await Clipboard.copy(code);
    await showToast({
      style: Toast.Style.Success,
      title: "Code copied to clipboard!",
    });
  };
  
  // Update codes every second for countdown
  useEffect(() => {
    // Initial load
    loadCodes();
    
    // Set up timer for refreshing codes
    const interval = setInterval(async () => {
      try {
        const authenticatorService = getAuthenticatorService();
        const authCodes = await authenticatorService.getAuthCodes();
        setCodes(authCodes);
      } catch (error) {
        // Silently handle errors in the interval to prevent UI disruption
        console.error("Error updating codes in timer:", error);
        // We don't reset the codes here to avoid flickering
      }
    }, 1000);
    
    setTimer(interval);
    
    // Clean up timer
    return () => {
      if (timer) {
        clearInterval(timer);
      }
    };
  }, []);
  
  return (
    <List
      isLoading={isLoading}
      searchBarPlaceholder="Search authenticator codes..."
      onSearchTextChange={setSearchText}
      isShowingDetail
      actions={
        <ActionPanel>
          <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={loadCodes} />
          <Action title="Sync with Server" icon={Icon.Download} onAction={syncCodes} />
          <Action title="Logout" icon={Icon.ExclamationMark} style={Action.Style.Destructive} onAction={handleLogout} />
        </ActionPanel>
      }
    >
      {filteredCodes.map((item) => {
        const progressColor = getProgressColor(item.progress || 0);
        const formattedCode = formatCode(item.code, item.digits);
        
        return (
          <List.Item
            key={item.id}
            title={item.name}
            subtitle={formattedCode}
            icon={{ source: Icon.Key, tintColor: progressColor }}
            detail={
              <List.Item.Detail
                metadata={
                  <List.Item.Detail.Metadata>
                    <List.Item.Detail.Metadata.Label title="Account" text={item.name} />
                    {item.issuer && (
                      <List.Item.Detail.Metadata.Label title="Issuer" text={item.issuer} />
                    )}
                    <List.Item.Detail.Metadata.Label title="Code" text={formattedCode} />
                    <List.Item.Detail.Metadata.TagList title="Type">
                      <List.Item.Detail.Metadata.TagList.Item
                        text={item.type.toUpperCase()}
                        color={item.type === "totp" ? Color.Green : Color.Blue}
                      />
                    </List.Item.Detail.Metadata.TagList>
                    {item.type === "totp" && item.remainingSeconds !== undefined && (
                      <List.Item.Detail.Metadata.Label
                        title="Refreshes in"
                        text={`${item.remainingSeconds} seconds`}
                      />
                    )}
                    {item.type === "totp" && item.progress !== undefined && (
                      <List.Item.Detail.Metadata.Progress
                        value={item.progress / 100}
                        color={progressColor}
                      />
                    )}
                  </List.Item.Detail.Metadata>
                }
              />
            }
            actions={
              <ActionPanel>
                <Action
                  title="Copy Code"
                  icon={Icon.Clipboard}
                  onAction={() => copyCode(item.code)}
                />
                <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={loadCodes} />
                <Action title="Sync with Server" icon={Icon.Download} onAction={syncCodes} />
              </ActionPanel>
            }
          />
        );
      })}
      
      {filteredCodes.length === 0 && !isLoading && (
        <List.EmptyView
          title="No authentication codes found"
          description="Sync with the server or add a new authentication code."
          icon={Icon.Key}
        />
      )}
    </List>
  );
}

// Helper function to format the code with spaces for readability
function formatCode(code: string, digits: number): string {
  if (digits === 6) {
    return `${code.substring(0, 3)} ${code.substring(3)}`;
  } else if (digits === 8) {
    return `${code.substring(0, 4)} ${code.substring(4)}`;
  }
  return code;
}

// Helper function to determine progress color based on remaining time
function getProgressColor(progress: number): Color {
  if (progress > 66) {
    return Color.Green;
  } else if (progress > 33) {
    return Color.Yellow;
  }
  return Color.Red;
}