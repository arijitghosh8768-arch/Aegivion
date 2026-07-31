import React from 'react';

export function Card({ children, className = '', ...props }: any) {
  return (
    <div className={`bg-[#0e1428] border border-gray-800 rounded-xl p-6 ${className}`} {...props}>
      {children}
    </div>
  );
}
