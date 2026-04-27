import * as React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

const httpClient = vi.fn()
vi.mock('../dataProvider/httpClient', () => ({
  default: (...args) => httpClient(...args),
}))

const notify = vi.fn()
const translate = (key) => key
vi.mock('react-admin', () => ({
  useTranslate: () => translate,
  useNotify: () => notify,
}))

vi.mock('@material-ui/core/styles', () => ({
  makeStyles: () => () => ({
    root: '',
    header: '',
    empty: '',
    secretField: '',
    secretActions: '',
  }),
}))

vi.mock('@material-ui/core', () => {
  const passthrough = (tag, testIdProp) =>
    React.forwardRef(({ children, ...props }, ref) => {
      const { ...rest } = props
      const testId = testIdProp ? rest[testIdProp] : undefined
      const cleaned = { ...rest }
      delete cleaned.classes
      delete cleaned.elevation
      delete cleaned.variant
      delete cleaned.size
      delete cleaned.fullWidth
      delete cleaned.startIcon
      delete cleaned.color
      delete cleaned.align
      delete cleaned.margin
      delete cleaned.InputProps
      delete cleaned.multiline
      return React.createElement(
        tag,
        { ref, ...cleaned, 'data-testid': testId },
        children,
      )
    })

  const Button = React.forwardRef(({ children, onClick, disabled }, ref) =>
    React.createElement(
      'button',
      {
        ref,
        onClick,
        disabled,
        'data-testid': 'btn-' + String(children).replace(/\s/g, '-'),
      },
      children,
    ),
  )
  const TextField = React.forwardRef(
    ({ value, onChange, onFocus, label }, ref) =>
      React.createElement('input', {
        ref,
        value: value ?? '',
        onChange,
        onFocus,
        'data-testid': 'tf-' + (label || 'unlabeled'),
        readOnly: false,
      }),
  )
  return {
    Box: passthrough('div'),
    Paper: passthrough('div'),
    Table: passthrough('table'),
    TableBody: passthrough('tbody'),
    TableCell: passthrough('td'),
    TableHead: passthrough('thead'),
    TableRow: passthrough('tr'),
    Typography: passthrough('div'),
    Tooltip: ({ children }) => children,
    IconButton: ({ onClick, children }) =>
      React.createElement(
        'button',
        { onClick, 'data-testid': 'icon-button' },
        children,
      ),
    Dialog: ({ open, children }) =>
      open
        ? React.createElement('div', { 'data-testid': 'dialog' }, children)
        : null,
    DialogTitle: passthrough('h2'),
    DialogContent: passthrough('div'),
    DialogContentText: passthrough('p'),
    DialogActions: passthrough('div'),
    Button,
    TextField,
  }
})

vi.mock('@material-ui/icons/DeleteOutline', () => ({
  default: () => React.createElement('span', null, 'del'),
}))
vi.mock('@material-ui/icons/FileCopy', () => ({
  default: () => React.createElement('span', null, 'cp'),
}))

vi.mock('../consts', () => ({
  REST_URL: '/api',
}))

import { AppPasswordPanel } from './AppPasswordPanel.jsx'

describe('<AppPasswordPanel />', () => {
  beforeEach(() => {
    httpClient.mockReset()
  })

  it('renders the empty-state copy when the API returns no items', async () => {
    httpClient.mockResolvedValueOnce({ json: [] })

    render(<AppPasswordPanel userId="user-1" />)

    await waitFor(() => {
      expect(httpClient).toHaveBeenCalledWith('/api/user/user-1/app-password')
    })
    expect(
      screen.getByText('resources.user.message.appPasswordsEmpty'),
    ).toBeInTheDocument()
  })

  it('renders rows for each item returned by the API', async () => {
    httpClient.mockResolvedValueOnce({
      json: [
        {
          id: 'ap1',
          name: 'iPhone Tempus',
          createdAt: '2026-04-27T00:00:00Z',
          lastUsedAt: null,
          revokedAt: null,
        },
      ],
    })

    render(<AppPasswordPanel userId="user-1" />)

    await waitFor(() => {
      expect(screen.getByText('iPhone Tempus')).toBeInTheDocument()
    })
    expect(
      screen.getByText('resources.user.message.appPasswordActive'),
    ).toBeInTheDocument()
  })

  it('shows the generated secret in a one-time dialog after creation', async () => {
    httpClient
      .mockResolvedValueOnce({ json: [] }) // initial load
      .mockResolvedValueOnce({
        json: { id: 'ap1', name: 'X', secret: 'super-secret-123' },
      }) // POST
      .mockResolvedValueOnce({ json: [] }) // reload after create

    render(<AppPasswordPanel userId="user-1" />)
    await waitFor(() => expect(httpClient).toHaveBeenCalledTimes(1))

    // open create dialog
    fireEvent.click(
      screen.getByTestId('btn-resources.user.actions.generateAppPassword'),
    )
    const nameInput = screen.getByTestId(
      'tf-resources.user.fields.appPasswordName',
    )
    fireEvent.change(nameInput, { target: { value: 'Phone' } })
    fireEvent.click(screen.getByTestId('btn-ra.action.create'))

    await waitFor(() => {
      expect(screen.getByDisplayValue('super-secret-123')).toBeInTheDocument()
    })
  })

  it('calls the revoke endpoint when the per-row revoke button is clicked', async () => {
    httpClient
      .mockResolvedValueOnce({
        json: [
          {
            id: 'ap1',
            name: 'iPhone',
            createdAt: '2026-04-27T00:00:00Z',
            lastUsedAt: null,
            revokedAt: null,
          },
        ],
      })
      .mockResolvedValueOnce({ json: { id: 'ap1' } })
      .mockResolvedValueOnce({ json: [] })

    render(<AppPasswordPanel userId="user-1" />)
    await waitFor(() => expect(screen.getByText('iPhone')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('icon-button'))

    await waitFor(() => {
      expect(httpClient).toHaveBeenCalledWith(
        '/api/user/user-1/app-password/ap1',
        { method: 'DELETE' },
      )
    })
  })
})
