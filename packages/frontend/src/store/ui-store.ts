import { create } from 'zustand'

interface UIState {
  isCollapsed: boolean
  toggleSidebar: () => void
}

export const useUIStore = create<UIState>((set: any) => ({
  isCollapsed: false,
  toggleSidebar: () => set((state: any) => ({ isCollapsed: !state.isCollapsed })),
}))
