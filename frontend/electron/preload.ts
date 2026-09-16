import { contextBridge, ipcRenderer } from "electron";
contextBridge.exposeInMainWorld("apex", {
  invoke: (operation: string, payload: Record<string, unknown>) =>
    ipcRenderer.invoke("apex:invoke", operation, payload),
  pick: (kind: "file" | "directory") => ipcRenderer.invoke("apex:pick", kind),
  openExports: () => ipcRenderer.invoke("apex:exports"),
  account: () => ipcRenderer.invoke("apex:account"),
  login: (input: unknown) => ipcRenderer.invoke("apex:login", input),
  logout: () => ipcRenderer.invoke("apex:logout"),
});
