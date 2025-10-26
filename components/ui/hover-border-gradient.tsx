// src/components/ui/hover-border-gradient.tsx
"use client";

import React, { useState } from "react";

interface HoverBorderGradientProps {
  children: React.ReactNode;
  containerClassName?: string;
  className?: string;
  as?: React.ElementType;
  disabled?: boolean;
}

export const HoverBorderGradient = ({
  children,
  containerClassName = "",
  className = "",
  as: Tag = "div",
  disabled = false,
}: HoverBorderGradientProps) => {
  const [isHovered, setIsHovered] = useState(false);

  if (disabled) {
    return (
      <Tag className={`${containerClassName} opacity-60 cursor-not-allowed`}>
        <div className={`p-[1px] rounded-lg ${className}`}>{children}</div>
      </Tag>
    );
  }

  return (
    <Tag
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={containerClassName}
    >
      <div
        className={`${
          isHovered
            ? "bg-[radial-gradient(circle_at_50%_50%,rgba(34,193,195,0.4),transparent_80%)]"
            : ""
        } transition-all duration-300 ease-in-out p-[1px] rounded-lg`}
      >
        <div className={className}>{children}</div>
      </div>
    </Tag>
  );
};