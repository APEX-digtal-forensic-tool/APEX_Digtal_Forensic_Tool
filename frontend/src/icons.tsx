/** Astryx Icon is the single UI icon entry point. Stock semantic glyphs are
 * used where available; domain glyphs use SVG components as its official API
 * documents. File-type artwork is separately supplied by Material Icon Theme. */
import { Icon, type IconName, type IconType } from "@astryxdesign/core/Icon";
import {
  ArchiveBoxIcon,
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ArrowRightOnRectangleIcon,
  ArrowLeftOnRectangleIcon,
  ChatBubbleLeftRightIcon,
  CircleStackIcon,
  DocumentDuplicateIcon,
  DocumentMagnifyingGlassIcon,
  FolderIcon,
  FolderOpenIcon,
  HomeIcon,
  PlusIcon,
  PlayIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  BookmarkSquareIcon,
} from "@heroicons/react/24/outline";
import type { CSSProperties } from "react";
type Props = { size?: number; className?: string; style?: CSSProperties };
function glyph(icon: IconName | IconType) {
  return function UIIcon({ size = 16, className = "", style }: Props) {
    return (
      <Icon
        icon={icon}
        className={`ui-icon ${className}`}
        style={{ width: size, height: size, fontSize: size, ...style }}
      />
    );
  };
}
export const Activity = glyph("arrowsUpDown");
export const AlertCircle = glyph("warning");
export const Archive = glyph(ArchiveBoxIcon);
export const ArrowDownToLine = glyph(ArrowDownTrayIcon);
export const ChevronDown = glyph("chevronDown");
export const ChevronRight = glyph("chevronRight");
export const Clock3 = glyph("clock");
export const Database = glyph(CircleStackIcon);
export const FileSearch = glyph(DocumentMagnifyingGlassIcon);
export const Files = glyph(DocumentDuplicateIcon);
export const Folder = glyph(FolderIcon);
export const FolderOpen = glyph(FolderOpenIcon);
export const HardDrive = glyph(ServerStackIcon);
export const LayoutDashboard = glyph(HomeIcon);
export const ListChecks = glyph("checkDouble");
export const LoaderCircle = glyph(ArrowPathIcon);
export const LogIn = glyph(ArrowRightOnRectangleIcon);
export const LogOut = glyph(ArrowLeftOnRectangleIcon);
export const PanelBottomClose = glyph("arrowDown");
export const PanelBottomOpen = glyph("arrowUp");
export const Play = glyph(PlayIcon);
export const Plus = glyph(PlusIcon);
export const RefreshCw = glyph(ArrowPathIcon);
export const Save = glyph(BookmarkSquareIcon);
export const Search = glyph("search");
export const SearchX = glyph("search");
export const Settings = glyph("wrench");
export const ShieldCheck = glyph(ShieldCheckIcon);
export const AssistantIcon = glyph(ChatBubbleLeftRightIcon);
export const X = glyph("close");
export function BrandLogo() {
  return (
    <span className="brand-logo">
      <img src="./assets/apex-logo.png" alt="APEX" draggable={false} />
    </span>
  );
}
