// satpam — cek secret key + basic request validation

import type { Env } from '../types';
import { timingSafeEqual } from '../utils/crypto';
import { errorResponse } from '../utils/response';

const MAX_BODY_SIZE = 10 * 1024; // 10KB maks

// cek secret key saweria — bales null kalo lolos
export async function authenticateRequest(
    request: Request,
    env: Env
): Promise<Response | null> {
    const secret = request.headers.get('Saweria-Secret-Key');

    if (!secret) {
        return errorResponse('Unauthorized: secret key nya mana', 403);
    }

    const isValid = await timingSafeEqual(secret, env.SAWERIA_SECRET);

    if (!isValid) {
        return errorResponse('Unauthorized: secret key nya salah', 403);
    }

    return null;
}

// cek content-type sama ukuran body
export function validateRequestBasics(request: Request): Response | null {
    const contentType = request.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
        return errorResponse('Content-Type harus application/json', 400);
    }

    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
        return errorResponse('Kegedean cuy, max 10KB', 413);
    }

    return null;
}
