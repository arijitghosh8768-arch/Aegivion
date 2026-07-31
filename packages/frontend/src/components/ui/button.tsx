import React from 'react';

export function Button({ children, className = '', ...props }: any) {
  return (
    <button className={`px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-white text-sm transition-all ${className}`} {...props}>
      {children}
    </button>
  );
}
