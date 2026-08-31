import { ReactNode, SVGProps } from "react";

// A small hand-rolled icon set — 20x20, 1.8px stroke, currentColor — so the
// app doesn't pull in an icon library for a dozen glyphs. Every icon takes
// the same props as a plain <svg>, so size/color follow from CSS/context.

type IconProps = SVGProps<SVGSVGElement>;

function base(children: ReactNode, props: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="18"
      height="18"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      {children}
    </svg>
  );
}

export const ShieldIcon = (p: IconProps) =>
  base(<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />, p);

export const ShieldCheckIcon = (p: IconProps) =>
  base(
    <>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </>,
    p
  );

export const GridIcon = (p: IconProps) =>
  base(
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </>,
    p
  );

export const ListIcon = (p: IconProps) =>
  base(
    <>
      <path d="M8 6h13" />
      <path d="M8 12h13" />
      <path d="M8 18h13" />
      <path d="M3 6h.01" />
      <path d="M3 12h.01" />
      <path d="M3 18h.01" />
    </>,
    p
  );

export const PlusCircleIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v8M8 12h8" />
    </>,
    p
  );

export const PlugIcon = (p: IconProps) =>
  base(
    <>
      <path d="M9 3v5M15 3v5" />
      <path d="M7 8h10v3a5 5 0 01-10 0V8z" />
      <path d="M12 16v5" />
    </>,
    p
  );

export const UsersIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6" />
      <path d="M16 4.2c1.6.5 2.7 2 2.7 3.8s-1.1 3.3-2.7 3.8" />
      <path d="M21 20c0-2.8-1.9-5.1-4.5-5.8" />
    </>,
    p
  );

export const RadarIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 12l5-5" />
      <path d="M12 7.5a4.5 4.5 0 100 9" />
    </>,
    p
  );

export const BellIcon = (p: IconProps) =>
  base(
    <>
      <path d="M7 9a5 5 0 0110 0v4.5l1.5 3H5.5L7 13.5V9z" />
      <path d="M9.5 19a2.5 2.5 0 005 0" />
    </>,
    p
  );

export const LogoutIcon = (p: IconProps) =>
  base(
    <>
      <path d="M15 4H7a2 2 0 00-2 2v12a2 2 0 002 2h8" />
      <path d="M11 12h10M18 8l3 4-3 4" />
    </>,
    p
  );

export const ClockAlertIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>,
    p
  );

export const CalendarIcon = (p: IconProps) =>
  base(
    <>
      <rect x="3.5" y="5" width="17" height="16" rx="2.2" />
      <path d="M3.5 10h17M8 3v4M16 3v4" />
    </>,
    p
  );

export const XCircleIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5l5 5M14.5 9.5l-5 5" />
    </>,
    p
  );

export const BanIcon = (p: IconProps) =>
  base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M6 18L18 6" />
    </>,
    p
  );

export const AlertTriangleIcon = (p: IconProps) =>
  base(
    <>
      <path d="M12 4.5l9 15.5H3l9-15.5z" />
      <path d="M12 10v4M12 17.5h.01" />
    </>,
    p
  );

export const ScrollTextIcon = (p: IconProps) =>
  base(
    <>
      <path d="M6 3.5h11a2 2 0 012 2V16a2 2 0 01-2 2H8" />
      <path d="M6 3.5A2 2 0 004 5.5V17a2 2 0 002 2h1" />
      <path d="M8 8h7M8 12h7" />
    </>,
    p
  );
