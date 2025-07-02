package devices

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"GADS/common/cli"
	"GADS/common/models"
	"GADS/provider/logger"
	"GADS/provider/providerutil"
)

// WebOS auto-connection constants
const (
	webosMaxRetries    = 5                // Maximum consecutive connection attempts
	webosRetryInterval = 30 * time.Second // Interval between connection attempts
	webosPauseAfterMax = 5 * time.Minute  // Pause duration after max retries reached
)

// WebOS retry tracking
var (
	webosRetryTracker = make(map[string]*webosRetryState)
	webosRetryMutex   sync.RWMutex
)

// webosRetryState tracks connection attempts for a WebOS device
type webosRetryState struct {
	deviceIP    string
	retryCount  int
	lastAttempt time.Time
	isPaused    bool
	pauseUntil  time.Time
}

func setupWebOSDevice(device *models.Device) {
	device.SetupMutex.Lock()
	defer device.SetupMutex.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)

	device.ProviderState = "preparing"
	logger.ProviderLogger.LogInfo("webos_device_setup", fmt.Sprintf("Running setup for WebOS device `%v`", device.UDID))

	err := cli.KillDeviceAppiumProcess(device.UDID)
	if err != nil {
		logger.ProviderLogger.LogError("webos_device_setup", fmt.Sprintf("Failed attempt to kill existing Appium processes for device `%s` - %v", device.UDID, err))
		ResetLocalDevice(device, "Failed to kill existing Appium processes.")
		return
	}

	appiumPort, err := providerutil.GetFreePort()
	if err != nil {
		logger.ProviderLogger.LogError("webos_device_setup", fmt.Sprintf("Could not allocate free host port for Appium for device `%v` - %v", device.UDID, err))
		ResetLocalDevice(device, "Failed to allocate free host port for Appium")
		return
	}
	device.AppiumPort = appiumPort

	err = getWebOSTVInfo(device)
	if err != nil {
		logger.ProviderLogger.LogError("webos_device_setup", fmt.Sprintf("Failed to get TV info for device `%v` - %v", device.UDID, err))
		ResetLocalDevice(device, "Failed to retrieve TV information.")
		return
	}

	go startAppium(device, &wg)
	go checkAppiumUp(device)

	select {
	case <-device.AppiumReadyChan:
		logger.ProviderLogger.LogInfo("webos_device_setup", fmt.Sprintf("Successfully started Appium for device `%v` on port %v", device.UDID, device.AppiumPort))
		break
	case <-time.After(30 * time.Second):
		logger.ProviderLogger.LogError("webos_device_setup", fmt.Sprintf("Did not successfully start Appium for device `%v` in 30 seconds", device.UDID))
		ResetLocalDevice(device, "Appium did not start within the expected time.")
		return
	}

	device.ProviderState = "live"
	wg.Wait()
}

func getWebOSTVHost(tvID string) (string, error) {
	// Check if the hostWithPort is in the format HOST_IP:PORT
	if matched, _ := regexp.MatchString(`^([0-9]{1,3}\.){3}[0-9]{1,3}:\d+$`, tvID); matched {
		host := strings.Split(tvID, ":")[0]
		return host, nil
	} else {
		return "", fmt.Errorf("invalid format for host: %s", tvID)
	}
}

func getWebOSTVInfo(device *models.Device) error {
	tvHost, err := getWebOSTVHost(device.UDID)
	if err != nil {
		return fmt.Errorf("failed to get TV host - %s", err)
	}

	url := fmt.Sprintf("http://%s:3000/api/getServiceList", tvHost)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get TV info - %s", err)
	}
	defer resp.Body.Close()

	var tvInfo models.WebOSTVInfo
	if err := json.NewDecoder(resp.Body).Decode(&tvInfo); err != nil {
		return fmt.Errorf("failed to decode TV info - %s", err)
	}

	// Update device information
	device.HardwareModel = tvInfo.Device.ModelName
	device.OSVersion = tvInfo.Device.FirmwareVersion
	device.IPAddress = tvInfo.Device.IP
	device.DeviceAddress = device.UDID

	// Extract dimensions from resolution
	if tvInfo.Device.Resolution != "" {
		dimensions := strings.Split(tvInfo.Device.Resolution, "x")
		if len(dimensions) == 2 {
			device.ScreenWidth = dimensions[0]
			device.ScreenHeight = dimensions[1]
		}
	}

	return nil
}

// connectWebOSDevice establishes a connection to a WebOS device using ares-setup-device
func connectWebOSDevice(deviceIP string) error {
	logger.ProviderLogger.LogInfo("webos_connection", fmt.Sprintf("Attempting to connect to WebOS device at %s", deviceIP))

	cmd := exec.Command("ares-setup-device", "add", deviceIP, "-n", deviceIP)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.ProviderLogger.LogError("webos_connection", fmt.Sprintf("Failed to connect to WebOS device %s - %s. Output: %s", deviceIP, err, string(output)))
		return fmt.Errorf("failed to connect to WebOS device %s: %s", deviceIP, err)
	}

	logger.ProviderLogger.LogInfo("webos_connection", fmt.Sprintf("Successfully connected to WebOS device %s. Output: %s", deviceIP, string(output)))
	return nil
}

// isWebOSDeviceConnected checks if a WebOS device is currently connected using ares-devices
func isWebOSDeviceConnected(deviceIP string) bool {
	connectedDevices := getConnectedDevicesWebOS()

	for _, device := range connectedDevices {
		if strings.Contains(device, deviceIP) {
			logger.ProviderLogger.LogDebug("webos_connection", fmt.Sprintf("WebOS device %s is connected", deviceIP))
			return true
		}
	}

	logger.ProviderLogger.LogDebug("webos_connection", fmt.Sprintf("WebOS device %s is not connected", deviceIP))
	return false
}

func getWebOSRetryState(deviceIP string) *webosRetryState {
	webosRetryMutex.RLock()
	defer webosRetryMutex.RUnlock()
	return webosRetryTracker[deviceIP]
}

func updateWebOSRetryState(deviceIP string, retryCount int, lastAttempt time.Time, isPaused bool, pauseUntil time.Time) {
	webosRetryMutex.Lock()
	defer webosRetryMutex.Unlock()

	webosRetryTracker[deviceIP] = &webosRetryState{
		deviceIP:    deviceIP,
		retryCount:  retryCount,
		lastAttempt: lastAttempt,
		isPaused:    isPaused,
		pauseUntil:  pauseUntil,
	}
}

func resetWebOSRetryState(deviceIP string) {
	webosRetryMutex.Lock()
	defer webosRetryMutex.Unlock()

	if _, exists := webosRetryTracker[deviceIP]; exists {
		webosRetryTracker[deviceIP] = &webosRetryState{
			deviceIP:    deviceIP,
			retryCount:  0,
			lastAttempt: time.Time{},
			isPaused:    false,
			pauseUntil:  time.Time{},
		}
	}
}

func shouldAttemptWebOSConnection(deviceIP string) bool {
	state := getWebOSRetryState(deviceIP)
	now := time.Now()

	if state == nil {
		// First time seeing this device, initialize state
		updateWebOSRetryState(deviceIP, 0, time.Time{}, false, time.Time{})
		return true
	}

	// If device is paused, check if pause period has ended
	if state.isPaused {
		if now.Before(state.pauseUntil) {
			return false // Still in pause period
		}
		// Pause period ended, reset retry count
		updateWebOSRetryState(deviceIP, 0, time.Time{}, false, time.Time{})
		return true
	}

	if state.retryCount >= webosMaxRetries {
		// Max retries reached, enter pause mode
		pauseUntil := now.Add(webosPauseAfterMax)
		updateWebOSRetryState(deviceIP, state.retryCount, state.lastAttempt, true, pauseUntil)
		logger.ProviderLogger.LogWarn("webos_auto_connect", fmt.Sprintf("WebOS device %s reached max retries (%d), pausing until %v", deviceIP, webosMaxRetries, pauseUntil))
		return false
	}

	// Check if enough time has passed since last attempt
	if !state.lastAttempt.IsZero() && now.Sub(state.lastAttempt) < webosRetryInterval {
		return false // Not enough time has passed
	}

	return true
}

// handleWebOSAutoConnection checks registered WebOS devices and attempts automatic connections
func handleWebOSAutoConnection(connectedDevices []string) {
	for _, dbDevice := range DBDeviceMap {
		// Only process WebOS devices that are enabled and registered
		if dbDevice.OS != "webos" || dbDevice.Usage == "disabled" {
			continue
		}

		deviceIP, err := getWebOSTVHost(dbDevice.UDID)
		if err != nil {
			logger.ProviderLogger.LogError("webos_auto_connect", fmt.Sprintf("Failed to extract IP from device UDID %s: %v", dbDevice.UDID, err))
			continue
		}

		isConnectedViaAres := isWebOSDeviceConnected(deviceIP)

		isInConnectedList := slices.Contains(connectedDevices, dbDevice.UDID)

		if isConnectedViaAres {
			state := getWebOSRetryState(deviceIP)
			if state != nil && state.retryCount > 0 {
				logger.ProviderLogger.LogInfo("webos_auto_connect", fmt.Sprintf("WebOS device %s (%s) is now connected, resetting retry count", dbDevice.UDID, deviceIP))
				resetWebOSRetryState(deviceIP)
			}
		} else if !isInConnectedList {
			if shouldAttemptWebOSConnection(deviceIP) {
				attemptWebOSConnection(deviceIP, dbDevice.UDID)
			}
		}
	}
}

// attemptWebOSConnection tries to connect to a WebOS device and updates retry state
func attemptWebOSConnection(deviceIP, deviceUDID string) {
	state := getWebOSRetryState(deviceIP)
	if state == nil {
		updateWebOSRetryState(deviceIP, 0, time.Time{}, false, time.Time{})
		state = getWebOSRetryState(deviceIP)
	}

	now := time.Now()
	newRetryCount := state.retryCount + 1

	logger.ProviderLogger.LogInfo("webos_auto_connect", fmt.Sprintf("Attempting to connect to WebOS device %s (%s) - attempt %d/%d", deviceUDID, deviceIP, newRetryCount, webosMaxRetries))

	err := connectWebOSDevice(deviceIP)
	if err != nil {
		logger.ProviderLogger.LogWarn("webos_auto_connect", fmt.Sprintf("Failed to connect to WebOS device %s (%s) - attempt %d/%d: %v", deviceUDID, deviceIP, newRetryCount, webosMaxRetries, err))
		updateWebOSRetryState(deviceIP, newRetryCount, now, false, time.Time{})

		if newRetryCount >= webosMaxRetries {
			pauseUntil := now.Add(webosPauseAfterMax)
			updateWebOSRetryState(deviceIP, newRetryCount, now, true, pauseUntil)
			logger.ProviderLogger.LogWarn("webos_auto_connect", fmt.Sprintf("WebOS device %s (%s) reached max retries (%d), pausing until %v", deviceUDID, deviceIP, webosMaxRetries, pauseUntil))
		}
	} else {
		logger.ProviderLogger.LogInfo("webos_auto_connect", fmt.Sprintf("Successfully connected to WebOS device %s (%s)", deviceUDID, deviceIP))
		resetWebOSRetryState(deviceIP)
	}
}

// getConnectedDevicesWebOS gets the connected WebOS devices using ares-devices
func getConnectedDevicesWebOS() []string {
	cmd := exec.Command("ares-devices")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.ProviderLogger.LogError("webos_device_detection", fmt.Sprintf("Failed to get WebOS devices: %s", err))
		return []string{}
	}

	var connectedDevices []string
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		// Skip empty lines and header
		if line == "" || strings.Contains(line, "name") || strings.Contains(line, "----") {
			continue
		}

		// ares-devices output format: "name                deviceinfo                connection  profile"
		// Example: "192.168.1.100:9922  tv (LG webOS TV OLED55C9PUA)  ssh         tv"
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// First field is the device ID (IP:PORT)
			deviceID := fields[0]
			connectedDevices = append(connectedDevices, deviceID)
		}
	}

	return connectedDevices
}