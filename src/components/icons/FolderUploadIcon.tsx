import React from 'react';

export default function FolderUploadIcon(props) {
    return (
        <svg
            width={props.width}
            height={props.height}
            viewBox={props.viewBox}
            fill="none"
            xmlns="http://www.w3.org/2000/svg">
            <path
                d="M24.333 23.3333H2.99967V7.33333C2.99967 6.6 2.39967 6 1.66634 6C0.933008 6 0.333008 6.6 0.333008 7.33333V23.3333C0.333008 24.8 1.53301 26 2.99967 26H24.333C25.0663 26 25.6663 25.4 25.6663 24.6667C25.6663 23.9333 25.0663 23.3333 24.333 23.3333Z"
                fill="black"
            />
            <path
                d="M26.9993 3.33366H17.666L15.786 1.45366C15.2793 0.946992 14.5993 0.666992 13.8927 0.666992H8.33268C6.86602 0.666992 5.67935 1.86699 5.67935 3.33366L5.66602 18.0003C5.66602 19.467 6.86602 20.667 8.33268 20.667H26.9993C28.466 20.667 29.666 19.467 29.666 18.0003V6.00033C29.666 4.53366 28.466 3.33366 26.9993 3.33366ZM22.9993 15.3337H12.3327C11.786 15.3337 11.466 14.707 11.7993 14.267L13.6393 11.827C13.906 11.467 14.4393 11.467 14.706 11.827L16.3327 14.0003L19.2927 10.0403C19.5593 9.68033 20.0927 9.68033 20.3594 10.0403L23.5327 14.267C23.866 14.707 23.546 15.3337 22.9993 15.3337Z"
                fill="black"
            />
        </svg>
    );
}

FolderUploadIcon.defaultProps = {
    height: 32,
    width: 32,
    viewBox: '0 0 32 32',
};
