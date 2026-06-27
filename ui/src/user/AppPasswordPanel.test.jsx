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
    tableWrap: '',
    secret: '',
  }),
}))

vi.mock('@material-ui/core', () => {
  const passthrough = (tag, displayName) => {
    const Component = React.forwardRef(({ children, ...props }, ref) => {
      const cleaned = { ...props }
      // Strip Material-UI-only props that don't belong on plain DOM nodes.
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
      return React.createElement(tag, { ref, ...cleaned }, children)
    })
    Component.displayName = displayName
    return Component
  }

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
  Button.displayName = 'MockButton'

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
  TextField.displayName = 'MockTextField'

  const Tooltip = ({ children }) => children
  Tooltip.displayName = 'MockTooltip'

  const IconButton = ({ onClick, children }) =>
    React.createElement(
      'button',
      { onClick, 'data-testid': 'icon-button' },
      children,
    )
  IconButton.displayName = 'MockIconButton'

  const Dialog = ({ open, children }) =>
    open
      ? React.createElement('div', { 'data-testid': 'dialog' }, children)
      : null
  Dialog.displayName = 'MockDialog'

  return {
    Box: passthrough('div', 'MockBox'),
    Paper: passthrough('div', 'MockPaper'),
    Table: passthrough('table', 'MockTable'),
    TableBody: passthrough('tbody', 'MockTableBody'),
    TableCell: passthrough('td', 'MockTableCell'),
    TableContainer: passthrough('div', 'MockTableContainer'),
    TableHead: passthrough('thead', 'MockTableHead'),
    TableRow: passthrough('tr', 'MockTableRow'),
    Typography: passthrough('div', 'MockTypography'),
    Tooltip,
    IconButton,
    Dialog,
    DialogTitle: passthrough('h2', 'MockDialogTitle'),
    DialogContent: passthrough('div', 'MockDialogContent'),
    DialogContentText: passthrough('p', 'MockDialogContentText'),
    DialogActions: passthrough('div', 'MockDialogActions'),
    Button,
    TextField,
  }
})

vi.mock('@material-ui/icons/DeleteOutline', () => {
  const MockDeleteOutlineIcon = () => React.createElement('span', null, 'del')
  MockDeleteOutlineIcon.displayName = 'MockDeleteOutlineIcon'
  return { default: MockDeleteOutlineIcon }
})

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
      expect(screen.getByText('super-secret-123')).toBeInTheDocument()
    })
  })

  it('copies the secret to the clipboard when the secret element is clicked', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })

    httpClient
      .mockResolvedValueOnce({ json: [] })
      .mockResolvedValueOnce({
        json: { id: 'ap1', name: 'X', secret: 'click-to-copy-me' },
      })
      .mockResolvedValueOnce({ json: [] })

    render(<AppPasswordPanel userId="user-1" />)
    await waitFor(() => expect(httpClient).toHaveBeenCalledTimes(1))

    fireEvent.click(
      screen.getByTestId('btn-resources.user.actions.generateAppPassword'),
    )
    fireEvent.change(
      screen.getByTestId('tf-resources.user.fields.appPasswordName'),
      { target: { value: 'Phone' } },
    )
    fireEvent.click(screen.getByTestId('btn-ra.action.create'))

    const secret = await screen.findByText('click-to-copy-me')
    fireEvent.click(secret)

    expect(writeText).toHaveBeenCalledWith('click-to-copy-me')
  })

  it('requires confirmation before revoking an app password', async () => {
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

    // Click the trash icon — should NOT fire DELETE yet, just open the dialog.
    fireEvent.click(screen.getByTestId('icon-button'))
    expect(httpClient).toHaveBeenCalledTimes(1) // still only the initial load

    // Confirm in the dialog — that's when DELETE actually fires.
    fireEvent.click(
      screen.getByTestId('btn-resources.user.actions.revokeAppPassword'),
    )

    await waitFor(() => {
      expect(httpClient).toHaveBeenCalledWith(
        '/api/user/user-1/app-password/ap1',
        { method: 'DELETE' },
      )
    })
  })

  it('does not revoke when the confirmation dialog is cancelled', async () => {
    httpClient.mockResolvedValueOnce({
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

    render(<AppPasswordPanel userId="user-1" />)
    await waitFor(() => expect(screen.getByText('iPhone')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('icon-button'))
    fireEvent.click(screen.getByTestId('btn-ra.action.cancel'))

    expect(httpClient).toHaveBeenCalledTimes(1) // no DELETE issued
  })
})
